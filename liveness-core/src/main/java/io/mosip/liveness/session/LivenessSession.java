package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.frame.EvidenceGate;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import io.mosip.liveness.streamauth.StreamAuthResult;
import io.mosip.liveness.streamauth.StreamAuthenticator;
import io.mosip.liveness.streamauth.StreamDigest;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Liveness session decision engine: one subject, one workflow, possibly several attempts.
 *
 * <p>All public methods are {@code synchronized}; events are applied in arrival order and every transition is
 * deterministic. <b>VERIFIED is assigned in exactly one place</b> ({@link #finishBound}), after: (1) the stream passive
 * check passed for this attempt, (2) the signed capture was BOUND by the {@link CaptureVerifier} (conservative capture
 * gate, OD-2), (3) every temporal-binding rule held for the RCAPTURE window, and (4) every frontal embedding of the
 * attempt matched the capture. Every other path — insufficient evidence, timeouts, missing embeddings, malformed or
 * replayed responses, model errors, clock jumps, device loss, cancel, shutdown — ends in a non-VERIFIED state.
 *
 * <p>Evidence enters only through two {@link EvidenceGate}s sharing the session id (frames and embeddings): items tagged
 * with another session, an older epoch, an out-of-order sequence or an arrival before the attempt's freshness floor are
 * dropped and counted, never used.
 *
 * <p><b>Attempt-level state that never depends on the bounded evidence store</b> (review finding 1): the frontal
 * embeddings of the whole attempt (subject ledger) and the count of attack-level frames. The store may evict records
 * (count/age bounds); decisions that need the whole attempt use these instead. If the subject ledger reaches its bound
 * the attempt fails closed ({@code ATTEMPT_EVIDENCE_OVERFLOW}) — it never evicts.
 *
 * <p><b>Timeouts are enforced on every event</b>, not only in {@link #tick()}, so a caller that never ticks cannot
 * stretch an attempt.
 *
 * <p><b>Arrival timestamps:</b> prefer {@link #tagArrival()}, which takes the sequence number and both timestamps from
 * the session itself at the frame-receipt boundary. {@link #tagArrival(long, long, long)} accepts a receipt time
 * captured earlier by the transport layer and validates it (not in the future, not older than
 * {@code maxArrivalAgeMs}, monotonic non-decreasing, wall/mono-consistent); rejected tags are null and counted.
 */
public final class LivenessSession implements AutoCloseable {

    /** Device identity as obtained from <em>verified</em> SBI deviceInfo/digitalId (caller's responsibility). */
    public static final class DeviceIdentity {
        public final String serial;
        public final String make;
        public final String model;
        public final String certification;

        public DeviceIdentity(String serial, String make, String model, String certification) {
            this.serial = Objects.requireNonNull(serial);
            this.make = make;
            this.model = model;
            this.certification = certification;
        }
    }

    /** What the caller must send as RCAPTURE: the nonce goes into the request's transactionId. */
    public static final class CaptureRequest {
        public final String transactionId;
        final long monoNanos;
        final long wallMillis;
        final long epoch;

        CaptureRequest(String transactionId, long monoNanos, long wallMillis, long epoch) {
            this.transactionId = transactionId;
            this.monoNanos = monoNanos;
            this.wallMillis = wallMillis;
            this.epoch = epoch;
        }
    }

    private static final SecureRandom RNG = new SecureRandom();
    /**
     * Security failures attributable to the SUBJECT: subject attack events (lockout per maxAttackEvents). Presentation
     * attacks (capture/stream/window PAD, subject change) are handled separately and are subject attack events too.
     */
    private static final Set<BindingResult.Reason> INTEGRITY = EnumSet.of(
            BindingResult.Reason.DEVICE_MISMATCH, BindingResult.Reason.SUBJECT_MISMATCH);
    /**
     * Security failures NOT attributable to the subject (owner decision 2026-10-24): unauthenticated (malformed before
     * authentication, bad signature, untrusted signer, invalid digitalId) or authenticated but unbound to this request
     * (transaction mismatch, replay). Rejected as security events; counted against the CHANNEL (persistent, locked over
     * maxChannelEvents, administrative reset only), never against the subject's attack counter.
     */
    private static final Set<BindingResult.Reason> CHANNEL_INTEGRITY = EnumSet.of(
            BindingResult.Reason.MALFORMED_RESPONSE, BindingResult.Reason.BAD_SIGNATURE, BindingResult.Reason.UNTRUSTED_DEVICE,
            BindingResult.Reason.DIGITAL_ID_INVALID, BindingResult.Reason.TRANSACTION_MISMATCH, BindingResult.Reason.REPLAYED_RESPONSE);
    /**
     * Device faults (owner decision 2026-10-24): only reachable for a response whose signature, trust, replay status and
     * device identity were verified (CaptureBinder order). Rejected, never evidence, no attack event; the attempt cap
     * still applies on retry.
     */
    private static final Set<BindingResult.Reason> DEVICE_FAULTS = EnumSet.of(
            BindingResult.Reason.TRANSACTION_ABSENT, BindingResult.Reason.MALFORMED_CONTENT, BindingResult.Reason.CAPTURE_STALE,
            BindingResult.Reason.CAPTURE_FROM_FUTURE, BindingResult.Reason.CAPTURE_OUTSIDE_WINDOW);
    /** Already non-attack retries; counted toward the device-fault diagnosis flag. */
    private static final Set<BindingResult.Reason> DEVICE_DIAGNOSTIC = EnumSet.of(
            BindingResult.Reason.DEVICE_ERROR, BindingResult.Reason.BAD_BIO_FORMAT);

    private final SessionPolicy policy;
    private final SessionClock clock;
    private final CaptureVerifier verifier;
    private final AttemptLedger ledger;
    private final String subjectKey;
    private final DeviceIdentity device;
    private final String channelKey;
    private final byte[] sessionId = new byte[16];
    private final EvidenceGate frameGate;
    private final EvidenceGate embeddingGate;
    private final SessionEvidenceStore store;
    private final StaticReplayDetector staticDetector;

    private State state = State.CREATED;
    private Reason reason = Reason.NONE;
    private BindingResult.Reason bindingReason;
    private String detail;
    private int attempt;
    private long epoch;
    private long sessionStartMono;
    private long sessionStartWall;
    private long attemptStartMono;
    private long offsetBaselineMs;
    private long readyMono;
    private Reason lastPassiveShortfall = Reason.INSUFFICIENT_EVIDENCE;
    private CaptureRequest pending;
    private String verifiedHash;
    private int deviceRecoveries;
    private long staleFrames, staleEmbeddings, invalidEvidence, lateResponses, rejectedArrivals;
    private int sessionDeviceFaults;
    // attempt-level (never evicted; reset by beginAttempt)
    private final List<float[]> attemptEmbeddings = new ArrayList<>();
    private boolean attemptEmbeddingOverflow;
    private int attemptAttackFrames;
    private EvidenceRecord lastUsableForStatic;   // predecessor for the residual cache (current attempt only)
    private Verification verifying;               // capture response being verified OUTSIDE the lock (phase B), or null

    /**
     * Decision inputs snapshotted under the lock when a valid capture response is accepted (phase A). The expensive
     * verification (phase B) runs on this snapshot without the lock; the result is applied (phase C) only if this
     * object is still {@link #verifying}, the state is still CAPTURE_IN_FLIGHT and the epoch is unchanged.
     */
    private static final class Verification {
        final CaptureRequest req;
        final long epoch;
        final long respMono;
        final Instant wallFrom;
        final Instant wallTo;
        final CaptureBinder.SessionContext ctx;
        final List<EvidenceRecord> window;
        final List<EvidenceRecord> recent;
        final StreamAuthenticator.Context authCtx;   // null unless stream authentication is required
        final boolean framesOverflow;

        Verification(CaptureRequest req, long epoch, long respMono, Instant wallFrom, Instant wallTo,
                     CaptureBinder.SessionContext ctx, List<EvidenceRecord> window, List<EvidenceRecord> recent,
                     StreamAuthenticator.Context authCtx, boolean framesOverflow) {
            this.req = req;
            this.epoch = epoch;
            this.respMono = respMono;
            this.wallFrom = wallFrom;
            this.wallTo = wallTo;
            this.ctx = ctx;
            this.window = window;
            this.recent = recent;
            this.authCtx = authCtx;
            this.framesOverflow = framesOverflow;
        }
    }
    // B1 prototype (attempt-level, never evicted; reset by beginAttempt)
    private final StreamAuthenticator streamAuth;
    private final java.util.LinkedHashMap<Long, long[]> attemptFrames = new java.util.LinkedHashMap<>();   // tagSeq -> {mono, evidence}
    private final java.util.Map<Long, byte[]> attemptFrameHashes = new java.util.HashMap<>();
    private boolean attemptFramesOverflow;
    private boolean streamAuthenticated;
    private String streamAuthResult;
    // arrival tagging
    private long nextSeq;
    private long lastTaggedMono;
    private boolean anyTagged;

    public LivenessSession(SessionPolicy policy, SessionClock clock, CaptureVerifier verifier, AttemptLedger ledger,
                           String subjectKey, DeviceIdentity device) {
        this(policy, clock, verifier, ledger, subjectKey, device, null);
    }

    /**
     * @param streamAuth B1 prototype verifier, or null (stream evidence unauthenticated). Required when the policy sets
     *                   {@code requireStreamAuthentication}.
     */
    public LivenessSession(SessionPolicy policy, SessionClock clock, CaptureVerifier verifier, AttemptLedger ledger,
                           String subjectKey, DeviceIdentity device, StreamAuthenticator streamAuth) {
        SessionPolicy pinned = Objects.requireNonNull(policy).copy();
        pinned.validate();                 // invalid configuration (e.g. unknown certification level) is rejected here
        this.policy = pinned;
        this.clock = Objects.requireNonNull(clock);
        this.verifier = Objects.requireNonNull(verifier);
        this.ledger = Objects.requireNonNull(ledger);
        this.subjectKey = Objects.requireNonNull(subjectKey);
        this.device = Objects.requireNonNull(device);
        this.channelKey = "device:" + device.serial;
        RNG.nextBytes(sessionId);
        if (pinned.requireStreamAuthentication && streamAuth == null) {
            throw new IllegalArgumentException("requireStreamAuthentication needs a StreamAuthenticator");
        }
        this.streamAuth = streamAuth;
        this.frameGate = EvidenceGate.forSession(sessionId);
        this.embeddingGate = EvidenceGate.forSession(sessionId);
        this.store = new SessionEvidenceStore(pinned.maxRecords, pinned.maxRecordAgeMs * 1_000_000L);
        this.staticDetector = new StaticReplayDetector(pinned.staticPhotoThreshold, pinned.staticMinPairs, pinned.staticMinVaryingPairs);
    }

    // =================================================================================================================
    // lifecycle
    // =================================================================================================================

    /** Starts the first attempt, unless policy or the ledger forbids it (fail closed). */
    public synchronized SessionOutcome start() {
        if (state != State.CREATED) {
            return outcome();
        }
        sessionStartMono = clock.monoNanos();
        sessionStartWall = clock.wallMillis();
        if (!ledger.trustworthy()) {            // tampered/unreadable counters: never start (fail closed, explicit)
            return terminal(State.FAILED_POLICY, Reason.LEDGER_UNTRUSTED, "attempt ledger failed authentication");
        }
        if (!certificationSatisfied()) {
            return terminal(State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT, "device=" + device.certification
                    + " required=" + policy.requiredCertification);
        }
        if (channelLocked()) {                  // before any attempt is consumed
            return terminal(State.FAILED_POLICY, Reason.CHANNEL_INTEGRITY_LOCKED, channelDiagnostic());
        }
        if (ledger.attempts(subjectKey) >= policy.maxAttempts) {
            return terminal(State.FAILED_MAX_RETRIES, Reason.MAX_RETRIES, "ledger");
        }
        if (ledger.attackEvents(subjectKey) > policy.maxAttackEvents) {
            return terminal(State.FAILED_MAX_RETRIES, Reason.ATTACK_LIMIT, "ledger");
        }
        beginAttempt(true);
        return outcome();
    }

    /** Starts a new attempt after RETRY_PENDING or REJECTED_ATTACK, if limits allow. Evidence never carries over. */
    public synchronized SessionOutcome retry() {
        if (state != State.RETRY_PENDING && state != State.REJECTED_ATTACK) {
            return outcome();
        }
        if (channelLocked()) {
            return terminal(State.FAILED_POLICY, Reason.CHANNEL_INTEGRITY_LOCKED, channelDiagnostic());
        }
        if (ledger.attackEvents(subjectKey) > policy.maxAttackEvents) {
            return terminal(State.FAILED_MAX_RETRIES, Reason.ATTACK_LIMIT, null);
        }
        if (ledger.attempts(subjectKey) >= policy.maxAttempts) {
            return terminal(State.FAILED_MAX_RETRIES, Reason.MAX_RETRIES, null);
        }
        beginAttempt(true);
        return outcome();
    }

    /** After ERROR_DEVICE, once the device is back: new epoch without consuming an attempt (bounded). */
    public synchronized SessionOutcome recoverDevice() {
        if (state != State.ERROR_DEVICE) {
            return outcome();
        }
        if (channelLocked()) {
            return terminal(State.FAILED_POLICY, Reason.CHANNEL_INTEGRITY_LOCKED, channelDiagnostic());
        }
        if (++deviceRecoveries > policy.maxDeviceRecoveries) {
            return terminal(State.FAILED_MAX_RETRIES, Reason.DEVICE_RECOVERY_LIMIT, null);
        }
        beginAttempt(false);
        return outcome();
    }

    public synchronized SessionOutcome cancel() {
        if (!state.terminal()) {
            terminal(State.CANCELLED, Reason.CANCELLED, null);
        }
        return outcome();
    }

    /** Shutdown (application exit, logout, navigation away): terminal, nothing can verify afterwards. */
    public synchronized SessionOutcome shutdown() {
        if (!state.terminal()) {
            terminal(State.SHUTDOWN, Reason.SHUTDOWN, null);
        }
        return outcome();
    }

    @Override
    public void close() {
        shutdown();
    }

    private void beginAttempt(boolean consumeAttempt) {
        if (consumeAttempt) {
            try {
                attempt = ledger.recordAttempt(subjectKey);
            } catch (RuntimeException e) {          // an attempt that cannot be recorded is never started (fail closed)
                terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "attempt ledger unavailable: " + e.getClass().getSimpleName());
                return;
            }
        }
        long now = clock.monoNanos();
        epoch = frameGate.advanceEpoch(now);
        embeddingGate.advanceEpoch(now);
        store.clear();
        attemptEmbeddings.clear();
        attemptEmbeddingOverflow = false;
        attemptAttackFrames = 0;
        lastUsableForStatic = null;
        verifying = null;
        attemptFrames.clear();
        attemptFrameHashes.clear();
        attemptFramesOverflow = false;
        streamAuthenticated = false;
        streamAuthResult = null;
        pending = null;
        attemptStartMono = now;
        offsetBaselineMs = clock.wallMillis() - now / 1_000_000L;
        lastPassiveShortfall = Reason.INSUFFICIENT_EVIDENCE;
        bindingReason = null;
        detail = null;
        set(State.CAPTURING, Reason.NONE);
    }

    // =================================================================================================================
    // evidence
    // =================================================================================================================

    /**
     * <b>Preferred.</b> Call on the thread that receives the frame, immediately on receipt (before decoding/processing).
     * Sequence number and timestamps come from the session, so the caller cannot back- or forward-date evidence.
     */
    public synchronized FrameTag tagArrival() {
        long mono = clock.monoNanos();
        return issueTag(mono, clock.wallMillis(), null);
    }

    /**
     * Preferred when B1 is used: as {@link #tagArrival()}, and hashes the received frame bytes (exact JPEG payload)
     * at the receipt boundary, so B1 can match the frame to the device-signed statement.
     */
    public synchronized FrameTag tagArrival(byte[] frameBytes) {
        long mono = clock.monoNanos();
        return issueTag(mono, clock.wallMillis(), frameBytes == null ? null : StreamDigest.sha256(frameBytes));
    }


    /**
     * Receipt time captured earlier by the transport layer. The contract: {@code monoNanos} is the session clock's
     * monotonic time at receipt, not in the future, at most {@code maxArrivalAgeMs} old, non-decreasing across calls;
     * {@code wallMillis} is the wall clock at the same instant (consistent with the current wall/mono offset within
     * {@code clockJumpToleranceMs}). Violations return null (counted); a null tag is never evidence. {@code seq} is the
     * transport's sequence number and is recorded for diagnostics only — the gate orders by the session's own counter.
     */
    public synchronized FrameTag tagArrival(long seq, long monoNanos, long wallMillis) {
        long now = clock.monoNanos();
        long offsetNow = clock.wallMillis() - now / 1_000_000L;
        long offsetTag = wallMillis - monoNanos / 1_000_000L;
        if (monoNanos - now > 0                                                   // future
                || now - monoNanos > policy.maxArrivalAgeMs * 1_000_000L          // stale
                || (anyTagged && monoNanos - lastTaggedMono < 0)                  // non-monotonic
                || Math.abs(offsetTag - offsetNow) > policy.clockJumpToleranceMs) { // wall/mono inconsistent
            rejectedArrivals++;
            return null;
        }
        return issueTag(monoNanos, wallMillis, null);
    }

    private FrameTag issueTag(long mono, long wall, byte[] hash) {
        anyTagged = true;
        lastTaggedMono = mono;
        FrameTag t = new FrameTag(sessionId, epoch, nextSeq++, mono, wall, hash);
        if (collecting()) {                         // received-frame log of the current attempt (B1)
            if (attemptFrames.size() >= policy.maxAttemptFrames) {
                attemptFramesOverflow = true;
            } else {
                attemptFrames.put(t.seq, new long[] {mono, 0});
                if (hash != null) {
                    attemptFrameHashes.put(t.seq, hash);
                }
            }
        }
        return t;
    }

    /** Pipeline result for a tagged frame. Dropped (and counted) unless the frame gate accepts it. */
    public synchronized void onFrameEvidence(FrameTag tag, FramePipeline.FrameEvidence ev) {
        if (ev == null) {
            staleFrames++;
            return;
        }
        onEvidence(tag, ev.faceCount, ev.eligible, ev.ineligibleReason, ev.padFused, ev.landmarks, ev.faceBox,
                ev.alignedGrey, ev.yawProxy);
    }

    /** Field-level entry point (tests and the mock harness); same gate and validation as {@link #onFrameEvidence}. */
    synchronized void onEvidence(FrameTag tag, int faceCount, boolean eligible, String why, Float pad, float[][] landmarks,
                                 float[] faceBox, float[] alignedGrey, float yaw) {
        enforceTimeouts();
        if (tag == null || !collecting()) {
            staleFrames++;
            return;
        }
        if (frameGate.check(tag.sessionId, tag.epoch, tag.seq, tag.monoNanos) != EvidenceGate.Verdict.ACCEPTED) {
            staleFrames++;
            return;
        }
        if (eligible && (pad == null || !Float.isFinite(pad) || pad < 0f || pad > 1f || alignedGrey == null)) {
            invalidEvidence++;               // invalid model output is never evidence (invariant I2)
            return;
        }
        EvidenceRecord r = new EvidenceRecord(tag.epoch, tag.seq, tag.monoNanos, tag.wallMillis, faceCount, eligible,
                why, pad, landmarks, faceBox, alignedGrey, yaw);
        store.append(r, clock.monoNanos());
        if (eligible && landmarks != null && alignedGrey != null) {
            // one residual pair per frame instead of re-registering every pair of the window on every frame
            StaticReplayDetector.cacheResiduals(lastUsableForStatic, r);
            lastUsableForStatic = r;
        }
        long[] fr = attemptFrames.get(tag.seq);
        if (fr != null) {
            fr[1] = 1;                              // evidence for this attempt (B1 coverage requirement)
        } else if (policy.requireStreamAuthentication) {
            attemptFramesOverflow = true;           // evidence without a received-frame record: cannot be authenticated
        }
        if (eligible && pad < policy.streamAttack) {
            attemptAttackFrames++;             // attempt-level: survives store eviction
        }
        evaluate();
    }

    /** Asynchronous embedding for a tagged frame. Dropped (and counted) unless the embedding gate accepts it. */
    public synchronized void onEmbedding(FrameTag tag, float[] embedding) {
        enforceTimeouts();
        if (tag == null || !collecting()) {
            staleEmbeddings++;
            return;
        }
        if (embeddingGate.check(tag.sessionId, tag.epoch, tag.seq, tag.monoNanos) != EvidenceGate.Verdict.ACCEPTED) {
            staleEmbeddings++;
            return;
        }
        if (!validEmbedding(embedding)) {
            invalidEvidence++;
            return;
        }
        EvidenceRecord r = store.find(tag.epoch, tag.seq);
        if (r != null && !r.eligible) {
            staleEmbeddings++;
            return;
        }
        float[] e = embedding.clone();
        if (r != null) {
            r.embedding = e;
        }
        // Subject ledger: frontal embeddings, plus embeddings whose record was already evicted (pose unknown; included
        // conservatively — a mismatch can only cause a fail-closed rejection).
        if (r == null || r.frontal(policy.frontalMaxAbsYaw)) {
            if (attemptEmbeddings.size() >= policy.maxAttemptEmbeddings) {
                attemptEmbeddingOverflow = true;
            } else {
                attemptEmbeddings.add(e);
            }
        }
    }

    /** Adapter for {@link io.mosip.liveness.pipeline.EmbeddingSampler.Listener}: the attachment must be the frame tag. */
    public void onEmbedding(long seq, long receivedNanos, float[] embedding, Object attachment) {
        onEmbedding(attachment instanceof FrameTag ? (FrameTag) attachment : null, embedding);
    }

    public synchronized void onDeviceDisconnected(String why) {
        if (!state.terminal() && state != State.ERROR_DEVICE) {
            pending = null;
            detail = why;
            set(State.ERROR_DEVICE, Reason.DEVICE_DISCONNECTED);
        }
    }

    public synchronized void onEngineError(Throwable t) {
        if (!state.terminal()) {
            terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, t == null ? null : t.getClass().getSimpleName());
        }
    }

    /** Applies time-based transitions; call periodically (and before reading the outcome). */
    public synchronized SessionOutcome tick() {
        enforceTimeouts();
        return outcome();
    }

    private void enforceTimeouts() {
        long now = clock.monoNanos();
        if (state != State.CREATED && !state.terminal() && elapsedMs(sessionStartMono, now) > policy.sessionTtlMs) {
            terminal(State.EXPIRED, Reason.SESSION_EXPIRED, null);
            return;
        }
        if (state == State.CAPTURING && elapsedMs(attemptStartMono, now) > policy.collectTimeoutMs) {
            set(State.RETRY_PENDING, lastPassiveShortfall);
        } else if (state == State.READY_FOR_CAPTURE && elapsedMs(readyMono, now) > policy.readyTimeoutMs) {
            set(State.RETRY_PENDING, Reason.CAPTURE_NOT_STARTED);
        } else if (state == State.CAPTURE_IN_FLIGHT && pending != null
                && elapsedMs(pending.monoNanos, now) > policy.captureTimeoutMs) {
            // pending == null while a received response is being verified (phase B): it arrived in time; TTL still applies
            pending = null;
            set(State.RETRY_PENDING, Reason.CAPTURE_TIMEOUT);
        }
    }

    // =================================================================================================================
    // capture
    // =================================================================================================================

    /** Only from READY_FOR_CAPTURE. Returns the request whose transactionId must be sent in RCAPTURE. */
    public synchronized CaptureRequest beginCapture() {
        enforceTimeouts();
        if (state != State.READY_FOR_CAPTURE) {
            throw new IllegalStateException("capture not allowed in state " + state);
        }
        long mono = clock.monoNanos();
        // The request's wall time is DERIVED from the attempt baseline (wall - mono at attempt start), never read now:
        // a transient wall step during this call would otherwise shift the binding window while the drift check at
        // the response (clock restored) sees nothing (adversarial review D1).
        pending = new CaptureRequest(new UUID(RNG.nextLong(), RNG.nextLong()).toString(), mono,
                offsetBaselineMs + mono / 1_000_000L, epoch);
        set(State.CAPTURE_IN_FLIGHT, Reason.NONE);
        return pending;
    }

    /**
     * RCAPTURE response for the request with {@code transactionId}. Responses for any other request (late, after a
     * retry/cancel/timeout, duplicates) are ignored and counted; they can never verify anything.
     *
     * <p>Three phases (capture-lock refactor): (A) under the lock, validate and consume the request and snapshot the
     * decision inputs; (B) WITHOUT the lock, run the binder and the B1 verifier on that snapshot (signature checks,
     * ISO/JPEG 2000 decode, model inference); (C) under the lock, apply the result only if nothing superseded it
     * (cancel, shutdown, expiry, device loss, stream attack, new attempt); otherwise discard it (counted as late).
     */
    public SessionOutcome onCaptureResponse(String transactionId, byte[] response) {
        Verification v;
        synchronized (this) {
            v = acceptResponse(transactionId);
            if (v == null) {
                return outcome();
            }
        }
        BindingResult b = null;
        Throwable bindError = null;
        try {
            b = verifier.bind(response, v.ctx, v.wallTo);
        } catch (Throwable t) {
            bindError = t;
        }
        StreamAuthResult ar = null;
        Throwable authError = null;
        boolean authRan = false;
        if (v.authCtx != null && bindError == null && b != null && b.outcome == BindingResult.Outcome.BOUND
                && b.captureEmbedding != null && b.signedDataSha256 != null && !v.framesOverflow) {
            authRan = true;
            try {
                ar = streamAuth.verify(response, v.authCtx, v.wallTo);
            } catch (Throwable t) {
                authError = t;
            }
        }
        synchronized (this) {
            return completeResponse(v, b, bindError, authRan, ar, authError);
        }
    }

    /** Phase A (lock held). Returns null if the response is not for the in-flight request or fails the clock check. */
    private Verification acceptResponse(String transactionId) {
        enforceTimeouts();                 // a response after the capture timeout or TTL is late, never bound
        if (state != State.CAPTURE_IN_FLIGHT || pending == null || transactionId == null
                || !pending.transactionId.equals(transactionId) || pending.epoch != epoch) {
            lateResponses++;
            return null;
        }
        CaptureRequest req = pending;
        pending = null;                    // consumed: duplicates and late copies are rejected from here on
        long respMono = clock.monoNanos();
        long drift = (clock.wallMillis() - respMono / 1_000_000L) - offsetBaselineMs;
        if (Math.abs(drift) > policy.clockJumpToleranceMs) {
            detail = "wall-mono offset moved by " + drift + " ms";
            set(State.RETRY_PENDING, Reason.CLOCK_DISCONTINUITY);
            return null;
        }
        long fromMono = req.monoNanos - policy.windowLatencyMs * 1_000_000L;
        List<EvidenceRecord> window = store.window(epoch, fromMono, respMono);
        List<EvidenceRecord> recent = store.window(epoch, respMono - policy.staticWindowMs * 1_000_000L, respMono);
        List<float[]> windowEmb = new ArrayList<>();
        for (EvidenceRecord r : window) {
            if (r.eligible && r.embedding != null && r.frontal(policy.frontalMaxAbsYaw)) {
                windowEmb.add(r.embedding);
            }
        }
        // Host wall-clock bounds of the window, derived from monotonic durations (immune to wall jumps after baseline).
        Instant wallFrom = Instant.ofEpochMilli(req.wallMillis - policy.windowLatencyMs);
        Instant wallTo = Instant.ofEpochMilli(req.wallMillis + elapsedMs(req.monoNanos, respMono));
        CaptureBinder.SessionContext ctx = new CaptureBinder.SessionContext(req.transactionId, device.serial, device.make,
                device.model, Instant.ofEpochMilli(sessionStartWall), windowEmb, wallFrom, wallTo);
        StreamAuthenticator.Context authCtx = null;
        if (policy.requireStreamAuthentication) {
            List<StreamAuthenticator.FrameRef> refs = new ArrayList<>();
            for (java.util.Map.Entry<Long, long[]> e : attemptFrames.entrySet()) {
                long mono = e.getValue()[0];
                refs.add(new StreamAuthenticator.FrameRef(e.getKey(), attemptFrameHashes.get(e.getKey()), e.getValue()[1] == 1,
                        mono - fromMono >= 0 && respMono - mono >= 0));
            }
            authCtx = new StreamAuthenticator.Context(req.transactionId, device.serial, wallFrom, wallTo, refs,
                    policy.b1MaxUncoveredTail, policy.b1MaxMissingInWindow, policy.b1StatementSkewMs);
        }
        verifying = new Verification(req, epoch, respMono, wallFrom, wallTo, ctx, window, recent, authCtx, attemptFramesOverflow);
        return verifying;
    }

    /** Phase C (lock held): apply the verification result unless it was superseded while the lock was released. */
    private SessionOutcome completeResponse(Verification v, BindingResult b, Throwable bindError, boolean authRan,
                                            StreamAuthResult ar, Throwable authError) {
        if (verifying != v) {
            lateResponses++;               // superseded (terminal, new attempt): the result is never applied
            return outcome();
        }
        verifying = null;
        enforceTimeouts();                 // the TTL may have expired while verifying
        if (state != State.CAPTURE_IN_FLIGHT || epoch != v.epoch) {
            lateResponses++;               // e.g. stream attack, device loss or expiry during verification
            return outcome();
        }
        if (bindError != null) {
            return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "binder threw " + bindError.getClass().getSimpleName());
        }
        if (b == null) {
            return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "binder returned null");
        }
        bindingReason = b.reason;
        switch (b.outcome) {
            case BOUND:
                return finishBound(b, v, authRan, ar, authError);
            case ATTACK:
                return attackEvent(Reason.CAPTURE_PAD_ATTACK);
            case UNCERTAIN:
                set(State.RETRY_PENDING, Reason.CAPTURE_UNCERTAIN);
                return outcome();
            case REJECTED:
                if (INTEGRITY.contains(b.reason)) {
                    return attackEvent(Reason.BINDING_INTEGRITY);
                }
                if (CHANNEL_INTEGRITY.contains(b.reason)) {
                    return channelEvent(b);
                }
                if (DEVICE_FAULTS.contains(b.reason)) {
                    return deviceFault(Reason.DEVICE_FAULT, b.reason);
                }
                if (DEVICE_DIAGNOSTIC.contains(b.reason)) {
                    return deviceFault(Reason.BINDING_REJECTED, b.reason);
                }
                set(State.RETRY_PENDING, Reason.BINDING_REJECTED);
                return outcome();
            case ERROR:
            default:
                return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "binding " + b.reason);
        }
    }

    /** Temporal-binding rules (plan section 4). The only place that assigns VERIFIED. */
    private SessionOutcome finishBound(BindingResult b, Verification v, boolean authRan, StreamAuthResult ar,
                                       Throwable authError) {
        if (b.captureEmbedding == null || b.signedDataSha256 == null) {
            return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "BOUND without capture embedding/hash");
        }
        CaptureRequest req = v.req;
        long respMono = v.respMono;
        List<EvidenceRecord> window = v.window;
        long fromMono = req.monoNanos - policy.windowLatencyMs * 1_000_000L;
        // 0. B1 prototype: authenticate the stream evidence before any stream-derived rule (design §6, §8)
        java.util.Set<Long> authenticated = null;
        if (policy.requireStreamAuthentication) {
            if (v.framesOverflow || attemptFramesOverflow) {   // read again at decision time: more conservative
                set(State.RETRY_PENDING, Reason.ATTEMPT_EVIDENCE_OVERFLOW);
                detail = "received-frame log overflow or evidence without a receipt record";
                return outcome();
            }
            if (authError != null) {
                return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "stream authenticator threw " + authError.getClass().getSimpleName());
            }
            if (!authRan || ar == null) {
                return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "stream authenticator returned null");
            }
            streamAuthResult = ar.outcome + "/" + ar.reason;
            if (ar.outcome != StreamAuthResult.Outcome.AUTHENTICATED) {
                // authentication failure: never VERIFIED, never reported as an attack/PAD verdict, no attack event
                set(State.RETRY_PENDING, ar.outcome == StreamAuthResult.Outcome.PROTOCOL_FAILURE
                        ? Reason.STREAM_AUTH_PROTOCOL_FAILURE : Reason.STREAM_AUTH_INTEGRITY_FAILURE);
                detail = ar.toString();
                return outcome();
            }
            authenticated = new java.util.HashSet<>(ar.coveredTags);
            List<EvidenceRecord> kept = new ArrayList<>();
            for (EvidenceRecord r : window) {
                if (authenticated.contains(r.seq)) {
                    kept.add(r);                    // uncovered trailing frames are removed from the decision
                }
            }
            window = kept;
        }
        List<EvidenceRecord> eligible = new ArrayList<>();
        for (EvidenceRecord r : window) {
            if (r.frozen() || r.faceCount > 1) {
                set(State.RETRY_PENDING, Reason.INTEGRITY_IN_WINDOW);
                detail = r.frozen() ? "frozen frame in window" : "multiple faces in window";
                return outcome();
            }
            if (r.eligible) {
                eligible.add(r);
            }
        }
        // 1. coverage
        if (eligible.size() < policy.windowMinFrames) {
            set(State.RETRY_PENDING, Reason.WINDOW_NOT_COVERED);
            detail = eligible.size() + " eligible frames in window";
            return outcome();
        }
        // 2. no gap larger than windowMaxGapMs, including the window edges
        long maxGapNanos = policy.windowMaxGapMs * 1_000_000L;
        long prev = fromMono;
        for (EvidenceRecord r : eligible) {
            if (r.monoNanos - prev > maxGapNanos) {
                set(State.RETRY_PENDING, Reason.STREAM_GAP_IN_WINDOW);
                return outcome();
            }
            prev = r.monoNanos;
        }
        if (respMono - prev > maxGapNanos) {
            set(State.RETRY_PENDING, Reason.STREAM_GAP_IN_WINDOW);
            return outcome();
        }
        // 3. per-frame PAD in the window: any attack-level frame is an attack; the median must reach the accept level
        List<Float> pads = new ArrayList<>();
        for (EvidenceRecord r : eligible) {
            if (r.pad < policy.streamAttack) {
                return attackEvent(Reason.WINDOW_PAD_ATTACK);
            }
            pads.add(r.pad);
        }
        if (median(pads) < policy.streamAccept) {
            set(State.RETRY_PENDING, Reason.WINDOW_PAD_INSUFFICIENT);
            return outcome();
        }
        // 4. the stream around the capture must not be a static image
        List<EvidenceRecord> recent = v.recent;                 // snapshotted at acceptance (same instant as before)
        if (authenticated != null) {
            List<EvidenceRecord> kept = new ArrayList<>();
            for (EvidenceRecord r : recent) {
                if (authenticated.contains(r.seq)) {
                    kept.add(r);
                }
            }
            recent = kept;
        }
        if (staticDetector.assess(eligibleOnly(recent)).verdict != StaticReplayDetector.Verdict.VARYING) {
            set(State.RETRY_PENDING, Reason.STATIC_IN_WINDOW);
            return outcome();
        }
        // 4b. PROPOSED (off by default; finding 3): frames that arrived after t_req + δ_lat (i.e. sensed after the
        //     device received the request) must themselves show variation. Excludes the latency allowance and the
        //     live→still transition pair. Known bypass: motion resumed before the response (see report).
        if (policy.requireVariationInCaptureWindow) {
            long sensedAfterReq = req.monoNanos + policy.windowLatencyMs * 1_000_000L;
            List<EvidenceRecord> during = new ArrayList<>();
            for (EvidenceRecord r : eligible) {
                if (r.monoNanos - sensedAfterReq > 0) {
                    during.add(r);
                }
            }
            if (new StaticReplayDetector(policy.staticPhotoThreshold, policy.captureWindowMinPairs,
                    policy.staticMinVaryingPairs).assess(during).verdict != StaticReplayDetector.Verdict.VARYING) {
                set(State.RETRY_PENDING, Reason.STATIC_IN_CAPTURE_WINDOW);
                return outcome();
            }
        }
        // 5. embeddings inside the window
        int windowEmb = 0;
        for (EvidenceRecord r : eligible) {
            if (r.embedding != null && r.frontal(policy.frontalMaxAbsYaw)) {
                windowEmb++;
            }
        }
        if (windowEmb < policy.windowMinEmbeddings) {
            set(State.RETRY_PENDING, Reason.MISSING_EMBEDDINGS);
            return outcome();
        }
        // 6. same subject for the WHOLE attempt: every ledger embedding (survives store eviction) must match the capture
        if (attemptEmbeddingOverflow) {
            set(State.RETRY_PENDING, Reason.ATTEMPT_EVIDENCE_OVERFLOW);
            return outcome();
        }
        for (float[] e : attemptEmbeddings) {
            if (cosine(b.captureEmbedding, e) < policy.subjectMinCosine) {
                return attackEvent(Reason.SUBJECT_CHANGED);
            }
        }
        verifiedHash = b.signedDataSha256;
        streamAuthenticated = authenticated != null;
        set(State.VERIFIED, Reason.OK);
        closeGates();
        return outcome();
    }

    // =================================================================================================================
    // passive evaluation
    // =================================================================================================================

    private void evaluate() {
        long now = clock.monoNanos();
        if (attemptAttackFrames >= policy.attackMinFrames) {
            attackEvent(Reason.STREAM_PAD_ATTACK);
            return;
        }
        if (state != State.CAPTURING) {
            return;                              // READY / IN_FLIGHT keep collecting window evidence only
        }
        List<EvidenceRecord> win = store.window(epoch, now - policy.passiveWindowMs * 1_000_000L, now);
        List<EvidenceRecord> el = new ArrayList<>();
        for (EvidenceRecord r : win) {
            if (r.faceCount > 1) {
                lastPassiveShortfall = Reason.MULTIPLE_FACES;
                return;
            }
            if (r.eligible) {
                el.add(r);
            }
        }
        if (el.size() < policy.passiveMinFrames
                || el.get(el.size() - 1).monoNanos - el.get(0).monoNanos < policy.passiveMinSpanMs * 1_000_000L) {
            lastPassiveShortfall = Reason.INSUFFICIENT_EVIDENCE;
            return;
        }
        List<EvidenceRecord> recent = store.window(epoch, now - policy.staticWindowMs * 1_000_000L, now);
        if (staticDetector.assess(eligibleOnly(recent)).verdict != StaticReplayDetector.Verdict.VARYING) {
            lastPassiveShortfall = Reason.STATIC_REPLAY_SUSPECT;
            return;
        }
        List<Float> pads = new ArrayList<>();
        for (EvidenceRecord r : el) {
            pads.add(r.pad);
        }
        if (median(pads) < policy.streamAccept) {
            lastPassiveShortfall = Reason.PASSIVE_UNCERTAIN_NO_CHALLENGE;   // no challenge engine yet: never accepted
            return;
        }
        readyMono = now;
        set(State.READY_FOR_CAPTURE, Reason.NONE);
    }

    // =================================================================================================================
    // helpers
    // =================================================================================================================

    /**
     * Unattributable security event: rejected, never evidence, NOT a subject attack event; counted against the channel
     * with diagnostic detail. Over the limit, the session ends FAILED_POLICY (fail closed) and the channel stays locked.
     */
    private SessionOutcome channelEvent(BindingResult b) {
        String diag = b.reason + (b.detail == null ? "" : ": " + b.detail);
        int n;
        try {
            n = ledger.recordChannelEvent(channelKey, diag);
        } catch (RuntimeException e) {
            return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "attempt ledger unavailable: " + e.getClass().getSimpleName());
        }
        if (n > policy.maxChannelEvents) {
            return terminal(State.FAILED_POLICY, Reason.CHANNEL_INTEGRITY_LOCKED, "channel " + channelKey + " locked after "
                    + n + " integrity events; last: " + diag);
        }
        pending = null;
        detail = "channel integrity: " + diag;
        set(State.REJECTED_ATTACK, Reason.CHANNEL_INTEGRITY);
        return outcome();
    }

    private boolean channelLocked() {
        return ledger.channelEvents(channelKey) > policy.maxChannelEvents;
    }

    private String channelDiagnostic() {
        return "channel " + channelKey + " locked (" + ledger.channelEvents(channelKey) + " integrity events; last: "
                + ledger.lastChannelReason(channelKey) + "); administrative reset required";
    }

    /** Rejected, never evidence, NO attack event; counted for diagnosis (session and persisted per subject). */
    private SessionOutcome deviceFault(Reason r, BindingResult.Reason why) {
        try {
            ledger.recordDeviceFault(subjectKey);
        } catch (RuntimeException e) {              // persistence broken: same fail-closed rule as for attempts
            return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "attempt ledger unavailable: " + e.getClass().getSimpleName());
        }
        sessionDeviceFaults++;
        pending = null;
        detail = "device fault: " + why;
        set(State.RETRY_PENDING, r);
        return outcome();
    }

    private SessionOutcome attackEvent(Reason r) {
        try {
            ledger.recordAttackEvent(subjectKey);
        } catch (RuntimeException e) {              // the event cannot be recorded: end the session (fail closed)
            return terminal(State.ERROR_ENGINE, Reason.ENGINE_ERROR, "attempt ledger unavailable: " + e.getClass().getSimpleName());
        }
        pending = null;
        set(State.REJECTED_ATTACK, r);
        return outcome();
    }

    private SessionOutcome terminal(State s, Reason r, String why) {
        pending = null;
        verifying = null;
        detail = why;
        set(s, r);
        closeGates();
        store.clear();
        attemptEmbeddings.clear();
        return outcome();
    }

    private void closeGates() {
        frameGate.close();
        embeddingGate.close();
    }

    private void set(State s, Reason r) {
        state = s;
        reason = r;
    }

    private boolean collecting() {
        return state == State.CAPTURING || state == State.READY_FOR_CAPTURE || state == State.CAPTURE_IN_FLIGHT;
    }

    private boolean certificationSatisfied() {
        String req = policy.requiredCertification;
        if (req == null) {
            return true;
        }
        if ("L1".equals(req)) {
            return "L1".equals(device.certification);
        }
        if ("L0".equals(req)) {
            return "L0".equals(device.certification) || "L1".equals(device.certification);
        }
        return false;                      // unreachable after validate(); fail closed regardless
    }

    private static List<EvidenceRecord> eligibleOnly(List<EvidenceRecord> rs) {
        List<EvidenceRecord> out = new ArrayList<>();
        for (EvidenceRecord r : rs) {
            if (r.eligible) {
                out.add(r);
            }
        }
        return out;
    }

    static boolean validEmbedding(float[] e) {
        if (e == null || e.length != 128) {
            return false;
        }
        double n = 0;
        for (float x : e) {
            if (!Float.isFinite(x)) {
                return false;
            }
            n += x * x;
        }
        return Math.abs(Math.sqrt(n) - 1.0) < 1e-2;      // the embedder returns L2-normalised vectors
    }

    private static float cosine(float[] a, float[] b) {
        double s = 0;
        for (int i = 0; i < a.length; i++) {
            s += a[i] * b[i];
        }
        return (float) s;
    }

    private static float median(List<Float> v) {
        List<Float> s = new ArrayList<>(v);
        Collections.sort(s);
        return s.get((s.size() - 1) / 2);   // lower median: conservative
    }

    private static long elapsedMs(long fromNanos, long toNanos) {
        return (toNanos - fromNanos) / 1_000_000L;
    }

    public synchronized State state() { return state; }

    public synchronized SessionOutcome outcome() {
        return new SessionOutcome(state, reason, bindingReason, attempt, ledger.attackEvents(subjectKey),
                state == State.VERIFIED ? verifiedHash : null, staleFrames, staleEmbeddings, invalidEvidence, lateResponses,
                rejectedArrivals, state == State.VERIFIED && streamAuthenticated, streamAuthResult, sessionDeviceFaults,
                sessionDeviceFaults >= policy.deviceFaultFlagThreshold
                        || ledger.deviceFaults(subjectKey) >= policy.deviceFaultFlagThreshold,
                ledger.channelEvents(channelKey), channelLocked(), detail);
    }
}
