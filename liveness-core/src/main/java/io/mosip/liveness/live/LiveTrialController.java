package io.mosip.liveness.live;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.integration.LivenessClientAdapter;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.CaptureVerifier;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionClock;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionOutcome.State;
import io.mosip.liveness.session.SessionPolicy;
import io.mosip.liveness.vision.Phase0Models;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Live trials on a real camera stream (via an SBI device or emulator), for the webcam demo. Each trial is ONE fresh
 * {@link LivenessSession} driven exactly as the Registration Client would drive it: frames go through
 * {@link LivenessClientAdapter} (receipt tag, real pipeline, session evidence); when — and only when — the session
 * itself reaches READY_FOR_CAPTURE, an RCAPTURE is issued and its signed response is verified by the real binder.
 *
 * <p>What this class does NOT do: it never decides liveness, never looks at which kind of test is being run, and never
 * maps "face detected" to anything. The displayed decision is the session outcome. Face box and PAD values are
 * displayed for transparency only.
 */
public final class LiveTrialController implements AutoCloseable {

    /** Issues an RCAPTURE with this transactionId and returns the raw response (SBI client in production). */
    @FunctionalInterface
    public interface CaptureFunction {
        byte[] rcapture(String transactionId) throws Exception;
    }

    /** One timeline entry: milliseconds since trial start, a coarse type and a short plain-English text. */
    public static final class Event {
        public final long tMs;
        public final String type;
        public final String text;

        Event(long tMs, String type, String text) {
            this.tMs = tMs;
            this.type = type;
            this.text = text;
        }
    }

    private static final int MAX_EVENTS = 300;
    private static final SecureRandom RNG = new SecureRandom();

    /** Snapshot for the UI / report. */
    public static final class Status {
        public int trial;
        /** Operator's label for the trial (e.g. live / video / photo). Recorded and shown only; the engine never sees it. */
        public String label;
        /** True if the trial was still running when it was abandoned (new trial started or window closed). */
        public boolean unfinished;
        public boolean trialActive;
        public String state = "IDLE";
        public String reason = "";
        public String bindingReason;
        public String detail;
        public int faceCount = -1;
        public boolean eligible;
        public String ineligibleReason;
        public Float lastPad;                 // P(real) of the latest eligible frame (stream)
        public Float medianPad;               // median of recent eligible frames (stream)
        public float[] faceBox;               // x, y, w, h in frame pixels
        public int frameWidth, frameHeight;
        public double frameProcessingMs;
        public double frameAgeMs;
        public Float capturePad;              // P(real) on the signed capture (binder)
        public Double bindMs;
        public boolean captureIssued;
        public int attackEvents, channelEvents;
        public String verdict = "";           // engine verdict text shown to the user
        /** Random per-trial identifier (not the engine's session id, which stays internal). */
        public String trialId;
        public long startedAtMs, finishedAtMs;
        public int attempt, maxAttempts;
        public int frames, eligibleFrames;
        public Float padMin, padMax;          // over eligible stream frames of this trial
        public Long readyMs;                  // trial start -> the session itself became ready for capture
        public Double captureRoundTripMs;     // RCAPTURE request -> raw response received
        public final Map<String, Double> spanMs = new LinkedHashMap<>();            // mean per-frame stage time
        public final Map<String, Integer> ineligibleCounts = new LinkedHashMap<>(); // why frames were not usable
        public final List<Event> events = new ArrayList<>();

        public boolean finished() {
            return "VERIFIED".equals(state) || "RETRY_PENDING".equals(state) || "REJECTED_ATTACK".equals(state)
                    || state.startsWith("FAILED") || "ERROR_ENGINE".equals(state) || "ERROR_DEVICE".equals(state)
                    || "EXPIRED".equals(state);
        }
    }

    /** Records the last binding result so the UI can show capture PAD and bind time (does not change it). */
    private static final class RecordingVerifier implements CaptureVerifier {
        final CaptureVerifier delegate;
        volatile BindingResult last;

        RecordingVerifier(CaptureVerifier d) {
            this.delegate = d;
        }

        @Override
        public BindingResult bind(byte[] response, CaptureBinder.SessionContext ctx, Instant now) {
            BindingResult b = delegate.bind(response, ctx, now);
            last = b;
            return b;
        }
    }

    private final Phase0Models models;
    private final FramePipeline.Config cfg;
    private final SessionPolicy policy;
    private final LivenessSession.DeviceIdentity device;
    private final CaptureFunction capture;
    private final RecordingVerifier verifier;
    private final AttemptLedger ledger = new AttemptLedger.InMemory();
    private final Deque<Float> recentPads = new ArrayDeque<>();

    private volatile byte[] latestFrame;
    private LivenessSession session;
    private LivenessClientAdapter adapter;
    private Thread captureThread;
    private int trial;
    private final Status status = new Status();
    private final List<Status> history = Collections.synchronizedList(new ArrayList<>());
    private volatile Throwable captureError;
    private final AtomicLong framesReceived = new AtomicLong();
    private volatile long lastFrameNanos;
    private final Map<String, long[]> spanAcc = new LinkedHashMap<>();    // stage -> {sum nanos, count}; under status lock
    private String lastStateKey = "";
    private String lastQualityKey = "";
    /** Tests only (set via the test-source LiveTestHooks): runs while poll() holds the status lock as a trial ends. */
    static volatile Runnable testHookTrialFinishing;

    public LiveTrialController(Phase0Models models, FramePipeline.Config cfg, SessionPolicy policy, CaptureVerifier verifier,
                               LivenessSession.DeviceIdentity device, CaptureFunction capture) {
        this.models = Objects.requireNonNull(models);
        this.cfg = Objects.requireNonNull(cfg);
        this.policy = Objects.requireNonNull(policy);
        this.verifier = new RecordingVerifier(Objects.requireNonNull(verifier));
        this.device = Objects.requireNonNull(device);
        this.capture = Objects.requireNonNull(capture);
    }

    /** Called on the stream-receipt thread for every received part. */
    public void onStreamFrame(byte[] jpeg) {
        latestFrame = jpeg;
        if (jpeg != null) {
            framesReceived.incrementAndGet();
            lastFrameNanos = System.nanoTime();
        }
        LivenessClientAdapter a;
        synchronized (this) {
            a = adapter;
        }
        if (a != null) {
            a.onStreamFrame(jpeg);
        }
    }

    public byte[] latestFrame() {
        return latestFrame;
    }

    /** Frames received from the device since start (all trials, and between trials). */
    public long framesReceived() {
        return framesReceived.get();
    }

    /** Milliseconds since the last received frame, or -1 if none has arrived yet. */
    public double lastFrameAgeMs() {
        long t = lastFrameNanos;
        return t == 0 ? -1 : (System.nanoTime() - t) / 1e6;
    }

    /** Starts a new, independent trial (a fresh session; the previous one is shut down). */
    public synchronized void startTrial() {
        startTrial(null);
    }

    /**
     * As {@link #startTrial()}, with an operator label stored next to the result. The label is never passed to the
     * session, pipeline or binder: every trial takes exactly the same decision path.
     */
    public synchronized void startTrial(String label) {
        recordIfUnfinished();
        stopTrial();
        trial++;
        recentPads.clear();
        verifier.last = null;
        captureError = null;
        // each trial is its own subject context: repeated trials do not consume each other's attempt budget;
        // the channel (device) counter is shared, as it would be on a registration PC
        session = new LivenessSession(policy, SessionClock.SYSTEM, verifier, ledger, "webcam-trial-" + trial, device);
        session.start();
        adapter = new LivenessClientAdapter(session, models, cfg);
        adapter.setObserver(this::onEvidence);
        captureThread = null;
        synchronized (status) {
            Status fresh = new Status();
            fresh.trial = trial;
            fresh.label = label;
            fresh.trialActive = true;
            fresh.trialId = "T" + trial + "-" + Long.toHexString(RNG.nextLong() & 0xFFFFFFFFFFL);
            fresh.startedAtMs = System.currentTimeMillis();
            fresh.maxAttempts = policy.maxAttempts;
            fresh.events.add(new Event(0, "start", "Trial started" + (label == null ? "" : " (label: " + label + ")")));
            spanAcc.clear();
            lastStateKey = "";
            lastQualityKey = "";
            copyInto(fresh, status);
        }
    }

    private void addEvent(String type, String text) {              // caller holds the status lock
        if (status.events.size() < MAX_EVENTS) {
            status.events.add(new Event(Math.max(0, System.currentTimeMillis() - status.startedAtMs), type, text));
        }
    }

    private void onEvidence(io.mosip.liveness.session.FrameTag tag, FramePipeline.FrameEvidence ev, long processingNanos) {
        synchronized (status) {
            status.frames++;
            if (ev.eligible) {
                status.eligibleFrames++;
            } else {
                status.ineligibleCounts.merge(ev.ineligibleReason == null ? "UNKNOWN" : ev.ineligibleReason, 1, Integer::sum);
            }
            String q = ev.eligible ? "OK" : String.valueOf(ev.ineligibleReason);
            if (!q.equals(lastQualityKey)) {
                lastQualityKey = q;
                addEvent("frame", ev.eligible ? "Face usable for assessment" : "Frame not usable: " + q);
            }
            if (ev.spans != null) {
                for (Map.Entry<String, Long> e : ev.spans.entrySet()) {
                    long[] acc = spanAcc.computeIfAbsent(e.getKey(), k -> new long[2]);
                    acc[0] += e.getValue();
                    acc[1]++;
                    status.spanMs.put(e.getKey(), acc[0] / (double) acc[1] / 1e6);
                }
            }
            if (ev.eligible && ev.padFused != null) {
                status.padMin = status.padMin == null ? ev.padFused : Math.min(status.padMin, ev.padFused);
                status.padMax = status.padMax == null ? ev.padFused : Math.max(status.padMax, ev.padFused);
            }
            status.faceCount = ev.faceCount;
            status.eligible = ev.eligible;
            status.ineligibleReason = ev.ineligibleReason;
            status.faceBox = ev.faceBox == null ? null : ev.faceBox.clone();
            status.frameWidth = ev.width;
            status.frameHeight = ev.height;
            status.frameProcessingMs = processingNanos / 1e6;
            status.frameAgeMs = (System.nanoTime() - tag.monoNanos) / 1e6;
            if (ev.eligible && ev.padFused != null) {
                status.lastPad = ev.padFused;
                recentPads.addLast(ev.padFused);
                while (recentPads.size() > 45) {            // ≈ 3 s at 15 fps, as the passive window
                    recentPads.removeFirst();
                }
                List<Float> sorted = new ArrayList<>(recentPads);
                Collections.sort(sorted);
                status.medianPad = sorted.get((sorted.size() - 1) / 2);
            }
        }
    }

    /** Advances the trial (timeouts; auto-capture once the SESSION is ready) and returns a snapshot. */
    public synchronized Status poll() {
        boolean finished = false;
        if (adapter != null) {
            SessionOutcome o = adapter.tick();
            if (o.state == State.READY_FOR_CAPTURE && captureThread == null) {
                LivenessSession.CaptureRequest req = adapter.beginCapture();
                LivenessClientAdapter a = adapter;
                final int myTrial = trial;
                synchronized (status) {
                    status.readyMs = Math.max(0, System.currentTimeMillis() - status.startedAtMs);
                    addEvent("capture", "Passive checks passed; signed capture requested");
                }
                captureThread = new Thread(() -> {
                    try {
                        long c0 = System.nanoTime();
                        byte[] raw = capture.rcapture(req.transactionId);
                        synchronized (status) {
                            if (status.trial == myTrial) {          // never write into a newer trial
                                status.captureRoundTripMs = (System.nanoTime() - c0) / 1e6;
                                addEvent("capture", "Signed capture received from the device");
                            }
                        }
                        a.onCaptureResponse(req.transactionId, raw);
                    } catch (Throwable t) {
                        captureError = t;
                        a.tick();
                    }
                }, "live-rcapture");
                captureThread.setDaemon(true);
                captureThread.start();
                o = adapter.tick();
            }
            synchronized (status) {
                status.attempt = o.attempt;
                status.maxAttempts = policy.maxAttempts;
                String key = o.state.name() + "/" + o.reason.name();
                if (!key.equals(lastStateKey)) {
                    lastStateKey = key;
                    addEvent("state", "Engine state: " + o.state.name() + (o.reason == SessionOutcome.Reason.NONE ? "" : " (" + o.reason.name() + ")"));
                }
                status.state = o.state.name();
                status.reason = o.reason.name();
                status.bindingReason = o.bindingReason == null ? null : o.bindingReason.name();
                status.detail = captureError != null ? "RCAPTURE failed: " + captureError : o.detail;
                status.captureIssued = captureThread != null;
                status.attackEvents = o.attackEvents;
                status.channelEvents = o.channelEvents;
                BindingResult b = verifier.last;
                status.capturePad = b == null ? null : b.padRealProbability;
                status.bindMs = b == null ? null : b.elapsedNanos / 1e6;
                status.verdict = verdict(o);
                if (status.finished() && status.trialActive) {
                    status.trialActive = false;
                    status.finishedAtMs = System.currentTimeMillis();
                    Status done = new Status();
                    copyInto(status, done);
                    history.add(done);
                    finished = true;
                    Runnable hook = testHookTrialFinishing;
                    if (hook != null) {
                        hook.run();                             // tests only: widens the race window
                    }
                }
            }
            // Never close the adapter while holding the status lock: close() joins the worker, whose observer
            // callback (onEvidence) takes the status lock.
            if (finished) {
                stopTrialKeepStatus();
            }
        }
        Status snap = new Status();
        synchronized (status) {
            copyInto(status, snap);
        }
        return snap;
    }

    /** The decision text is a pure function of the session outcome. */
    static String verdict(SessionOutcome o) {
        switch (o.state) {
            case VERIFIED:
                return "VERIFIED by the engine (stream PAD passed, signed capture bound, capture PAD >= gate)";
            case RETRY_PENDING:
                return "NOT ACCEPTED - retry: " + o.reason;
            case REJECTED_ATTACK:
                return "REJECTED: " + o.reason + (o.bindingReason == null ? "" : " (" + o.bindingReason + ")");
            case CAPTURING:
                return "collecting stream evidence...";
            case READY_FOR_CAPTURE:
            case CAPTURE_IN_FLIGHT:
                return "capturing signed image...";
            default:
                return o.state + " / " + o.reason;
        }
    }

    public List<Status> history() {
        synchronized (history) {
            return new ArrayList<>(history);
        }
    }

    private void stopTrialKeepStatus() {
        if (adapter != null) {
            LivenessClientAdapter a = adapter;
            adapter = null;
            a.setObserver(null);
            a.close();
        }
        session = null;
    }

    private void stopTrial() {
        stopTrialKeepStatus();
    }

    @Override
    public synchronized void close() {
        recordIfUnfinished();
        stopTrial();
    }

    /**
     * Ends the running trial at the operator's request. The result is recorded as CANCELLED / unfinished: it is never a
     * decision, and nothing about it can be read as a pass.
     */
    public synchronized void cancelTrial() {
        if (adapter == null) {
            return;
        }
        synchronized (status) {
            if (status.trialActive) {
                status.state = "CANCELLED";
                status.reason = "CANCELLED";
                status.bindingReason = null;
                status.verdict = "Cancelled before a decision";
                status.detail = "The trial was cancelled by the operator.";
                status.trialActive = false;
                status.unfinished = true;
                status.finishedAtMs = System.currentTimeMillis();
                addEvent("state", "Engine state: CANCELLED (operator)");
                Status done = new Status();
                copyInto(status, done);
                history.add(done);
            }
        }
        stopTrialKeepStatus();                      // joins the worker; never while holding the status lock
    }

    /** Keeps an abandoned (still running) trial in the history, marked unfinished, so no attempt silently vanishes. */
    private void recordIfUnfinished() {
        synchronized (status) {
            if (status.trialActive) {
                status.trialActive = false;
                status.unfinished = true;
                status.finishedAtMs = System.currentTimeMillis();
                Status done = new Status();
                copyInto(status, done);
                history.add(done);
            }
        }
    }

    private static void copyInto(Status a, Status b) {
        b.trial = a.trial;
        b.label = a.label;
        b.unfinished = a.unfinished;
        b.trialActive = a.trialActive;
        b.state = a.state;
        b.reason = a.reason;
        b.bindingReason = a.bindingReason;
        b.detail = a.detail;
        b.faceCount = a.faceCount;
        b.eligible = a.eligible;
        b.ineligibleReason = a.ineligibleReason;
        b.lastPad = a.lastPad;
        b.medianPad = a.medianPad;
        b.faceBox = a.faceBox == null ? null : a.faceBox.clone();
        b.frameWidth = a.frameWidth;
        b.frameHeight = a.frameHeight;
        b.frameProcessingMs = a.frameProcessingMs;
        b.frameAgeMs = a.frameAgeMs;
        b.capturePad = a.capturePad;
        b.bindMs = a.bindMs;
        b.captureIssued = a.captureIssued;
        b.attackEvents = a.attackEvents;
        b.channelEvents = a.channelEvents;
        b.verdict = a.verdict;
        b.trialId = a.trialId;
        b.startedAtMs = a.startedAtMs;
        b.finishedAtMs = a.finishedAtMs;
        b.attempt = a.attempt;
        b.maxAttempts = a.maxAttempts;
        b.frames = a.frames;
        b.eligibleFrames = a.eligibleFrames;
        b.padMin = a.padMin;
        b.padMax = a.padMax;
        b.readyMs = a.readyMs;
        b.captureRoundTripMs = a.captureRoundTripMs;
        b.spanMs.clear();
        b.spanMs.putAll(a.spanMs);
        b.ineligibleCounts.clear();
        b.ineligibleCounts.putAll(a.ineligibleCounts);
        b.events.clear();
        b.events.addAll(a.events);                 // Event is immutable
    }
}
