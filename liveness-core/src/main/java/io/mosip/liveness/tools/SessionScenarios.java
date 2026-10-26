package io.mosip.liveness.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.binding.VisionCaptureAnalyzer;
import io.mosip.liveness.frame.EncodedFrame;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.sbi.MjpegParser;
import io.mosip.liveness.sbi.SbiClient;
import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.FrameTag;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionClock;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionOutcome.State;
import io.mosip.liveness.session.SessionPolicy;
import io.mosip.liveness.vision.Phase0Models;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the full decision engine ({@link LivenessSession}: EvidenceGate, temporal binding, CaptureBinder) end to end
 * against the mock SBI, one fresh session per scenario, with the real stream, the real pipeline and real JWS
 * verification. The mock selects per RCAPTURE: capture mode, what the UNSIGNED stream shows during the capture, and a
 * device clock skew.
 *
 * <p>Security criterion: no attack/fault scenario may end VERIFIED. Genuine scenarios are reported (usability), not
 * asserted: with the placeholder PAD model and synthetic motion they say nothing about real-device behaviour.
 * Evidence class: [MOCK].
 */
final class SessionScenarios {
    private SessionScenarios() {}

    static final ObjectMapper JSON = new ObjectMapper();

    static final class Scenario {
        final String name, captureMode, streamDuringCapture;
        final double skewS;
        final boolean genuine;
        final String expectation;
        /** Session or binding reasons (or pseudo-reason tokens) meaning the attack was stopped BY THE CONTROL IT TARGETS. */
        final List<String> intended;
        // ---- test-only knobs (never production configuration) ----
        final Map<String, String> policy = new LinkedHashMap<>();
        long captureAtMs;                  // earliest capture, ms after session start (0 = as soon as READY)
        long captureDelayAfterReadyMs;     // wait this long in READY before beginCapture
        long wallJumpAfterBeginMs;         // permanent wall-clock step right after beginCapture
        long wallTransientAtBeginMs;       // wall step applied only while beginCapture runs
        Long arrivalSkewMs;                // transport-supplied arrival time = now + skew (validated tagArrival)
        boolean noTick;                    // never call tick(); observe via outcome() only
        long responseDelayMs;              // hold the RCAPTURE response before handing it to the session
        boolean silentDuringDelay;         // stop the stream during that hold: no events at all reach the session
        boolean decidedWithoutCapture;     // the targeted control acts before any capture is issued
        boolean knownResidual;             // no session control can stop it by construction (e.g. T17)
        String b1Mode = "";                // B1 prototype device fault (mock customOpts.phase0B1Mode)

        Scenario(String name, String captureMode, String stream, double skewS, boolean genuine, String expectation,
                 String... intended) {
            this.name = name;
            this.captureMode = captureMode;
            this.streamDuringCapture = stream;
            this.skewS = skewS;
            this.genuine = genuine;
            this.expectation = expectation;
            this.intended = Arrays.asList(intended);
        }

        Scenario policy(String k, String v) {
            policy.put(k, v);
            return this;
        }

        Scenario set(java.util.function.Consumer<Scenario> c) {
            c.accept(this);
            return this;
        }
    }

    static final List<Scenario> ALL = Arrays.asList(
            new Scenario("genuine", "best", "normal", 0, true, "VERIFIED, or a fail-closed retry (usability)"),
            new Scenario("genuine-skew+3s", "best", "normal", 3, true, "as genuine (skew inside tolerance)"),
            new Scenario("skew+30s", "best", "normal", 30, false, "BINDING_INTEGRITY(CAPTURE_OUTSIDE_WINDOW)", "CAPTURE_OUTSIDE_WINDOW"),
            new Scenario("stream-pause-during-capture", "best", "pause", 0, false, "STREAM_GAP_IN_WINDOW / WINDOW_NOT_COVERED", "STREAM_GAP_IN_WINDOW", "WINDOW_NOT_COVERED", "INSUFFICIENT_STREAM_EVIDENCE"),
            new Scenario("stream-inject-other-subject", "best", "inject", 0, false, "SUBJECT_CHANGED", "SUBJECT_CHANGED", "SUBJECT_MISMATCH"),
            new Scenario("stream-static-during-capture", "best", "static", 0, false, "not VERIFIED (see report: known gap)", "STATIC_IN_WINDOW", "STATIC_IN_CAPTURE_WINDOW"),
            new Scenario("capture-swap-other-person", "swap-alt", "normal", 0, false, "SUBJECT_MISMATCH", "SUBJECT_MISMATCH", "SUBJECT_CHANGED"),
            new Scenario("replay-previous-response", "replay", "normal", 0, false, "BINDING_INTEGRITY(TRANSACTION_MISMATCH)", "TRANSACTION_MISMATCH", "REPLAYED_RESPONSE"),
            new Scenario("stale", "stale", "normal", 0, false, "BINDING_INTEGRITY(CAPTURE_STALE)", "CAPTURE_STALE"),
            new Scenario("txn-mismatch", "txn-mismatch", "normal", 0, false, "BINDING_INTEGRITY", "TRANSACTION_MISMATCH"),
            new Scenario("tamper", "tamper", "normal", 0, false, "BINDING_INTEGRITY(BAD_SIGNATURE)", "BAD_SIGNATURE"),
            new Scenario("untrusted-key", "untrusted-key", "normal", 0, false, "BINDING_INTEGRITY(UNTRUSTED_DEVICE)", "UNTRUSTED_DEVICE"),
            new Scenario("expired-cert", "expired-cert", "normal", 0, false, "BINDING_INTEGRITY(UNTRUSTED_DEVICE)", "UNTRUSTED_DEVICE"),
            new Scenario("other-device", "other-device", "normal", 0, false, "BINDING_INTEGRITY(DEVICE_MISMATCH)", "DEVICE_MISMATCH"),
            new Scenario("device-error", "error", "normal", 0, false, "BINDING_REJECTED(DEVICE_ERROR)", "DEVICE_ERROR"),
            new Scenario("whole-stream", "best", "normal", 0, false, "for --motion static-replay/jitter mocks: STATIC_REPLAY_SUSPECT", "STATIC_REPLAY_SUSPECT"),
            // ---- adversarial verification (mock started with --switch-image; person changes 4 s after STREAM opens) ----
            new Scenario("subject-switch", "best", "normal", 0, false, "session SUBJECT_CHANGED (A only before the window)", "SUBJECT_CHANGED")
                    .policy("readyTimeoutMs", "30000").set(x -> x.captureAtMs = 6_000),
            new Scenario("subject-switch-evict-count", "best", "normal", 0, false, "SUBJECT_CHANGED after A's records are evicted by count", "SUBJECT_CHANGED")
                    .policy("readyTimeoutMs", "30000").policy("maxRecords", "40").set(x -> x.captureAtMs = 9_000),
            new Scenario("subject-switch-evict-age", "best", "normal", 0, false, "SUBJECT_CHANGED after A's records are evicted by age", "SUBJECT_CHANGED")
                    .policy("readyTimeoutMs", "30000").policy("maxRecordAgeMs", "16000").set(x -> x.captureAtMs = 22_000),
            // ---- adversarial verification (plain animated mock) ----
            new Scenario("ledger-overflow", "best", "normal", 0, false, "ATTEMPT_EVIDENCE_OVERFLOW", "ATTEMPT_EVIDENCE_OVERFLOW")
                    .policy("maxAttemptEmbeddings", "5"),
            new Scenario("clock-jump-before-response", "best", "normal", 0, false, "CLOCK_DISCONTINUITY", "CLOCK_DISCONTINUITY")
                    .set(x -> x.wallJumpAfterBeginMs = 10_000),
            new Scenario("clock-transient-at-request", "best", "normal", 0, true, "genuine: no false attack event (D1 regression)")
                    .set(x -> x.wallTransientAtBeginMs = -600_000),
            new Scenario("forged-arrival-future", "best", "normal", 0, false, "every forward-dated frame rejected; never ready", "ARRIVAL_TIMESTAMPS_REJECTED")
                    .set(x -> { x.arrivalSkewMs = 50L; x.decidedWithoutCapture = true; }),
            new Scenario("forged-arrival-stale", "best", "normal", 0, false, "every back-dated frame rejected; never ready", "ARRIVAL_TIMESTAMPS_REJECTED")
                    .set(x -> { x.arrivalSkewMs = -1_500L; x.decidedWithoutCapture = true; }),
            new Scenario("no-tick-capture-timeout", "best", "normal", 0, false, "late response ignored (timeout enforced by frame events)", "CAPTURE_TIMEOUT")
                    .set(x -> { x.noTick = true; x.responseDelayMs = 16_000; }),
            new Scenario("no-tick-capture-timeout-silent", "best", "normal", 0, false, "late response ignored (no events at all until the response)", "CAPTURE_TIMEOUT")
                    .set(x -> { x.noTick = true; x.responseDelayMs = 16_000; x.silentDuringDelay = true; }),
            new Scenario("no-tick-ready-timeout", "best", "normal", 0, false, "beginCapture refused after the ready timeout", "CAPTURE_NOT_STARTED")
                    .set(x -> { x.noTick = true; x.captureDelayAfterReadyMs = 6_000; x.decidedWithoutCapture = true; }),
            // ---- T17: same-person video on the unauthenticated stream, photo/print of that person at the sensor ----
            new Scenario("same-person-video-injection", "swap", "normal", 0, false,
                    "no stream control can stop it by construction; only capture PAD / subject threshold remain")
                    .set(x -> x.knownResidual = true),
            // ---- B1 prototype (run with --b1; intended tokens are verifier reasons) ----
            new Scenario("b1-genuine", "best", "normal", 0, true, "VERIFIED with streamAuthenticated, or a fail-closed retry"),
            new Scenario("b1-omit", "best", "normal", 0, false, "PROTOCOL STATEMENT_MISSING", "STATEMENT_MISSING").set(x -> x.b1Mode = "omit"),
            new Scenario("b1-replay-previous-statement", "best", "normal", 0, false, "INTEGRITY (statement of an earlier capture)", "WRONG_TRANSACTION", "CAPTURE_NOT_BOUND").set(x -> x.b1Mode = "replay-previous"),
            new Scenario("b1-old-carrier", "best", "normal", 0, false, "statement at the old top-level field is not read: STATEMENT_MISSING", "STATEMENT_MISSING").set(x -> x.b1Mode = "top-level"),
            new Scenario("b1-stream-delayed", "best", "normal", 0, false, "PROTOCOL STALE_FRAMES (authentic frames delayed by an attacker)", "STALE_FRAMES").set(x -> x.b1Mode = "delay-stream"),
            new Scenario("b1-wrong-txn", "best", "normal", 0, false, "INTEGRITY WRONG_TRANSACTION", "WRONG_TRANSACTION").set(x -> x.b1Mode = "wrong-txn"),
            new Scenario("b1-tamper", "best", "normal", 0, false, "INTEGRITY BAD_SIGNATURE", "BAD_SIGNATURE").set(x -> x.b1Mode = "tamper"),
            new Scenario("b1-rogue-key", "best", "normal", 0, false, "INTEGRITY UNTRUSTED_SIGNER", "UNTRUSTED_SIGNER").set(x -> x.b1Mode = "rogue-key"),
            new Scenario("b1-device2-key", "best", "normal", 0, false, "INTEGRITY SIGNER_NOT_CAPTURE_DEVICE", "SIGNER_NOT_CAPTURE_DEVICE").set(x -> x.b1Mode = "device2-key"),
            new Scenario("b1-gap", "best", "normal", 0, false, "PROTOCOL SEQUENCE_GAP", "SEQUENCE_GAP").set(x -> x.b1Mode = "gap"),
            new Scenario("b1-reorder", "best", "normal", 0, false, "PROTOCOL SEQUENCE_REORDER", "SEQUENCE_REORDER").set(x -> x.b1Mode = "reorder"),
            new Scenario("b1-stale", "best", "normal", 0, false, "PROTOCOL STALE_STATEMENT", "STALE_STATEMENT").set(x -> x.b1Mode = "stale"),
            new Scenario("b1-wrong-capture", "best", "normal", 0, false, "INTEGRITY CAPTURE_NOT_BOUND", "CAPTURE_NOT_BOUND").set(x -> x.b1Mode = "wrong-capture"),
            new Scenario("b1-stream-inject", "best", "inject", 0, false, "INTEGRITY FRAME_NOT_COVERED (injected frames in window)", "FRAME_NOT_COVERED"),
            new Scenario("b1-stream-pause", "best", "pause", 0, false, "PROTOCOL MISSING_FRAMES_IN_WINDOW (suppressed genuine frames)", "MISSING_FRAMES_IN_WINDOW"),
            new Scenario("b1-whole-stream-replaced", "best", "normal", 0, false,
                    "INTEGRITY FRAME_NOT_COVERED (T17: attacker video replaces every part; mock --stream-replace-image)", "FRAME_NOT_COVERED"));

    /** Test clock: real monotonic time; wall clock with an adjustable offset (no system clock is touched). */
    static final class ScenarioClock implements SessionClock {
        volatile long wallOffsetMs;

        @Override
        public long monoNanos() { return System.nanoTime(); }

        @Override
        public long wallMillis() { return System.currentTimeMillis() + wallOffsetMs; }
    }

    static Map<String, Object> run(Phase0Cli.Args a) throws Exception {
        JwsVerifier verifier = JwsVerifier.fromPem(Paths.get(a.get("trust")));
        SbiClient sbi = new SbiClient(a.getInt("port", 4501));
        JsonNode info = verifier.verify(sbi.info().get(0).path("deviceInfo").asText(), new java.util.Date()).payload;
        JsonNode digitalId = verifier.verify(info.path("digitalId").asText(), new java.util.Date()).payload;
        LivenessSession.DeviceIdentity device = new LivenessSession.DeviceIdentity(digitalId.path("serialNo").asText(),
                digitalId.path("make").asText(null), digitalId.path("model").asText(null), info.path("certification").asText(null));
        List<String> wanted = a.has("scenarios") ? Arrays.asList(a.get("scenarios").split(",")) : null;
        boolean genuineStream = !"static".equals(a.get("stream-kind", "live"));
        int repeat = a.getInt("repeat", 1);

        Map<String, Object> r = new LinkedHashMap<>();
        r.put("evidence_class", "[MOCK] mock SBI + placeholder PAD + synthetic motion; decision-logic evidence only. "
                + "Not real-device validation; session consistency does not establish stream authenticity or PAD accuracy");
        List<Map<String, Object>> results = new ArrayList<>();
        Map<String, Integer> classes = new java.util.TreeMap<>();
        try (Phase0Models models = Phase0Cli.models(a)) {
            FramePipeline.Config cfg = Phase0Cli.pipelineConfig(a);
            cfg.embedEvery = a.getInt("embed-every", 3);
            cfg.asyncEmbedding = true;
            CaptureBinder binder = new CaptureBinder(verifier, verifier, new VisionCaptureAnalyzer(models),
                    CaptureBinder.Policy.conservativeAcceptGate());
            try (FramePipeline pipe = new FramePipeline(models, cfg)) {
                for (Scenario sc : ALL) {
                    if (wanted != null ? !wanted.contains(sc.name) : (sc.name.equals("whole-stream") || ALL.indexOf(sc) > 15)) {
                        continue;
                    }
                    for (int k = 0; k < repeat; k++) {
                        Map<String, Object> m = runOne(sc, sbi, pipe, binder, device, a);
                        if (repeat > 1) {
                            m.put("repeat", k + 1);
                        }
                        boolean wholeStream = sc.name.equals("whole-stream");
                        boolean attackScenario = !sc.genuine && !(wholeStream && genuineStream);
                        if (attackScenario) {
                            String cls = classify(sc, m, wholeStream);
                            m.put("classification", cls);
                            classes.merge(cls, 1, Integer::sum);
                        } else {
                            m.put("false_attack_event", State.REJECTED_ATTACK.name().equals(m.get("state")));
                        }
                        results.add(m);
                        System.err.println(sc.name + " -> " + m.get("outcome") + "  " + m.getOrDefault("classification", "(genuine)"));
                    }
                }
            }
            r.put("models", models.versions);
        }
        r.put("scenarios", results);
        r.put("classification_legend", "EXERCISED_INTENDED = stopped by the control the scenario targets; "
                + "FAILED_CLOSED_OTHER = not VERIFIED, but stopped by a different check (targeted control not demonstrated); "
                + "NOT_EXERCISED = the attack never reached the targeted control (e.g. no capture issued); "
                + "FAIL_VERIFIED = attack reached VERIFIED; FAIL_VERIFIED_KNOWN_RESIDUAL = same, for a documented residual risk");
        r.put("classification_counts", classes);
        return r;
    }

    static String classify(Scenario sc, Map<String, Object> m, boolean wholeStream) {
        if (State.VERIFIED.name().equals(m.get("state"))) {
            return sc.knownResidual ? "FAIL_VERIFIED_KNOWN_RESIDUAL" : "FAIL_VERIFIED";
        }
        boolean intended = sc.intended.contains(m.get("reason")) || sc.intended.contains(m.get("binding_reason"))
                || sc.intended.contains(m.get("b1_reason"))
                || (sc.intended.contains("ARRIVAL_TIMESTAMPS_REJECTED") && ((Number) m.get("rejected_arrival_timestamps")).longValue() > 0
                        && Boolean.FALSE.equals(m.get("capture_issued")) && ((Number) m.get("evidence_frames")).longValue() == 0);
        if (intended) {
            return "EXERCISED_INTENDED";
        }
        if (!wholeStream && !sc.decidedWithoutCapture && !Boolean.TRUE.equals(m.get("capture_issued"))) {
            return "NOT_EXERCISED";
        }
        return "FAILED_CLOSED_OTHER";
    }

    private static SessionPolicy policyFor(Scenario sc, Phase0Cli.Args a) throws Exception {
        SessionPolicy policy = new SessionPolicy();
        policy.requireVariationInCaptureWindow = a.has("window-variation");   // PROPOSED rule, off unless requested
        policy.requireStreamAuthentication = a.has("b1");                      // B1 PROTOTYPE, off unless requested
        for (Map.Entry<String, String> e : sc.policy.entrySet()) {            // test-only overrides, recorded in output
            java.lang.reflect.Field f = SessionPolicy.class.getField(e.getKey());
            Class<?> t = f.getType();
            f.set(policy, t == int.class ? (Object) Integer.parseInt(e.getValue()) : t == long.class ? (Object) Long.parseLong(e.getValue())
                    : t == float.class ? (Object) Float.parseFloat(e.getValue()) : t == double.class ? (Object) Double.parseDouble(e.getValue())
                    : t == boolean.class ? (Object) Boolean.parseBoolean(e.getValue()) : e.getValue());
        }
        return policy;
    }

    private static Map<String, Object> runOne(Scenario sc, SbiClient sbi, FramePipeline pipe, CaptureBinder binder,
                                              LivenessSession.DeviceIdentity device, Phase0Cli.Args a) throws Exception {
        SessionPolicy policy = policyFor(sc, a);
        ScenarioClock clock = new ScenarioClock();
        LivenessSession session = new LivenessSession(policy, clock, binder, new AttemptLedger.InMemory(),
                "scenario-" + sc.name, device, policy.requireStreamAuthentication
                        ? new io.mosip.liveness.streamauth.StreamDigestVerifier(JwsVerifier.fromPem(Paths.get(a.get("trust")))) : null);
        pipe.setEmbeddingListener(session::onEmbedding);
        session.start();
        InputStream stream = sbi.openStream(device.serial, "0", 90_000);
        AtomicBoolean stop = new AtomicBoolean();
        long[] counts = new long[5];          // frames, corrupt, pipeline errors, tags rejected, evidence frames
        Thread reader = new Thread(() -> {
            MjpegParser parser = new MjpegParser(stream);
            long seq = 0;
            try {
                while (!stop.get()) {
                    MjpegParser.Part part = parser.next();
                    if (!part.isValid()) {
                        counts[1]++;
                        continue;
                    }
                    counts[0]++;
                    FrameTag tag;
                    if (sc.arrivalSkewMs == null) {                 // trusted: session clock + counter at receipt
                        tag = policy.requireStreamAuthentication ? session.tagArrival(part.jpeg) : session.tagArrival();
                    } else {                                        // a transport that forges its receipt times
                        tag = session.tagArrival(seq, System.nanoTime() + sc.arrivalSkewMs * 1_000_000L,
                                clock.wallMillis() + sc.arrivalSkewMs);
                    }
                    if (tag == null) {
                        counts[3]++;
                        seq++;
                        continue;
                    }
                    counts[4]++;
                    try {
                        session.onFrameEvidence(tag, pipe.process(new EncodedFrame(seq, tag.monoNanos, tag.wallMillis,
                                "image/jpeg", part.jpeg), tag));
                    } catch (Exception e) {
                        counts[2]++;
                        session.onEngineError(e);
                    }
                    seq++;
                }
            } catch (IOException e) {
                if (!stop.get()) {
                    session.onDeviceDisconnected(e.getClass().getSimpleName());
                }
            }
        }, "session-stream");
        reader.setDaemon(true);
        reader.start();

        long t0 = System.nanoTime();
        String txn = null;
        long readyAfterMs = -1;
        long readySince = -1;
        boolean beginRefused = false;
        List<String> attempts = new ArrayList<>();
        SessionOutcome o = sc.noTick ? session.outcome() : session.tick();
        while (!o.state.terminal() && o.state != State.REJECTED_ATTACK && o.state != State.ERROR_DEVICE
                && System.nanoTime() - t0 < 80_000_000_000L) {
            long sinceStart = (System.nanoTime() - t0) / 1_000_000;
            if (o.state == State.RETRY_PENDING) {
                attempts.add(o.toString());
                if (txn != null || sc.decidedWithoutCapture || sc.name.equals("whole-stream")) {
                    break;                      // capture exercised (or the targeted control already decided): done
                }
                o = session.retry();            // operator retries until a capture is issued, within the attempt limit
                readySince = -1;
                continue;
            }
            if (o.state == State.READY_FOR_CAPTURE) {
                if (readySince < 0) {
                    readySince = sinceStart;
                    readyAfterMs = sinceStart;
                }
                boolean due = sinceStart >= sc.captureAtMs && sinceStart - readySince >= sc.captureDelayAfterReadyMs;
                if (due) {
                    LivenessSession.CaptureRequest req;
                    clock.wallOffsetMs += sc.wallTransientAtBeginMs;
                    try {
                        req = session.beginCapture();
                    } catch (IllegalStateException e) {
                        beginRefused = true;
                        o = session.outcome();
                        continue;
                    } finally {
                        clock.wallOffsetMs -= sc.wallTransientAtBeginMs;
                    }
                    clock.wallOffsetMs += sc.wallJumpAfterBeginMs;
                    txn = req.transactionId;
                    ObjectNode opts = JSON.createObjectNode().put("phase0CaptureMode", sc.captureMode)
                            .put("phase0StreamDuringCapture", sc.streamDuringCapture).put("phase0ClockSkewS", sc.skewS);
                    if (policy.requireStreamAuthentication) {
                        opts.put("phase0B1Mode", sc.b1Mode);   // mock-only fault hook; B1 itself needs no request field
                    }
                    byte[] resp = sbi.rcaptureFace(txn, "Developer", "Registration", 10_000, a.getInt("capture-time-ms", 1500), opts);
                    if (sc.responseDelayMs > 0) {
                        if (sc.silentDuringDelay) {
                            stop.set(true);
                            closeQuietly(stream);
                        }
                        Thread.sleep(sc.responseDelayMs);
                    }
                    o = session.onCaptureResponse(txn, resp);
                    if (sc.silentDuringDelay) {
                        break;
                    }
                    continue;
                }
            }
            Thread.sleep(20);
            o = sc.noTick ? session.outcome() : session.tick();
        }
        stop.set(true);
        closeQuietly(stream);
        reader.join(5000);
        SessionOutcome fin = session.outcome();
        session.shutdown();
        pipe.setEmbeddingListener(null);
        o = fin;

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("scenario", sc.name);
        m.put("capture_mode", sc.captureMode);
        m.put("stream_during_capture", sc.streamDuringCapture);
        m.put("skew_s", sc.skewS);
        m.put("test_policy_overrides", sc.policy);
        m.put("expectation", sc.expectation);
        m.put("outcome", o.toString());
        m.put("state", o.state.name());
        m.put("reason", o.reason.name());
        m.put("binding_reason", o.bindingReason == null ? null : o.bindingReason.name());
        if (attempts.isEmpty() || !attempts.get(attempts.size() - 1).equals(o.toString())) {
            attempts.add(o.toString());
        }
        m.put("attempts", attempts);
        m.put("attack_events", o.attackEvents);
        m.put("channel_events", o.channelEvents);
        m.put("channel_locked", o.channelLocked);
        m.put("ready_after_ms", readyAfterMs);
        m.put("capture_issued", txn != null);
        m.put("begin_capture_refused", beginRefused);
        m.put("frames", counts[0]);
        m.put("evidence_frames", counts[4]);
        m.put("corrupt_parts", counts[1]);
        m.put("pipeline_errors", counts[2]);
        m.put("dropped_stale_frames", o.droppedStaleFrames);
        m.put("dropped_stale_embeddings", o.droppedStaleEmbeddings);
        m.put("invalid_evidence", o.invalidEvidence);
        m.put("ignored_late_responses", o.ignoredLateResponses);
        m.put("rejected_arrival_timestamps", o.rejectedArrivalTimestamps);
        m.put("window_variation_rule", policy.requireVariationInCaptureWindow);
        m.put("stream_auth_required", policy.requireStreamAuthentication);
        m.put("stream_authenticated", o.streamAuthenticated);
        m.put("b1_result", o.streamAuthResult);
        m.put("b1_reason", o.streamAuthResult == null ? null : o.streamAuthResult.substring(o.streamAuthResult.indexOf('/') + 1));
        m.put("detail", o.detail);
        return m;
    }

    private static void closeQuietly(InputStream s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // expected when closing mid-read
        }
    }
}
