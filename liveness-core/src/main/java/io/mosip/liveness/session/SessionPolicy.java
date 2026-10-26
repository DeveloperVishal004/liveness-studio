package io.mosip.liveness.session;

/**
 * Session decision parameters. <b>All values are PROVISIONAL</b>: chosen for the mock device and [SIM] fixtures so the
 * logic can be tested. None is calibrated on real devices or representative data; production values come from plan
 * tasks T3.1 (device timing), T6.3 (PAD calibration) and owner ratification. The capture-PAD accept gate is configured
 * on the {@code CaptureBinder.Policy} (conservative 0.80 default, OD-2).
 */
public final class SessionPolicy {
    private static final long MAX_MS = 86_400_000L;

    // ---- attempts, timeouts -------------------------------------------------------------------------------------------
    public int maxAttempts = 3;
    /** Attack/integrity events tolerated before the subject context is locked out (0 = first event locks out). */
    public int maxAttackEvents = 1;
    public int maxDeviceRecoveries = 2;
    /**
     * Channel-integrity events (unauthenticated or unbound responses) tolerated per capture channel before the channel
     * is locked (fail closed; administrative reset only). Mirrors maxAttackEvents: 1 means the second event locks.
     */
    public int maxChannelEvents = 1;
    public long collectTimeoutMs = 10_000;
    public long readyTimeoutMs = 5_000;
    public long captureTimeoutMs = 15_000;
    public long sessionTtlMs = 120_000;

    // ---- passive (stream) decision ------------------------------------------------------------------------------------
    public long passiveWindowMs = 3_000;
    public int passiveMinFrames = 8;
    public long passiveMinSpanMs = 1_000;
    /** Stream PAD: median P(real) of eligible frames in the window must reach this. Placeholder model; uncalibrated. */
    public float streamAccept = 0.80f;
    /** Any eligible frame below this counts toward an attack verdict. */
    public float streamAttack = 0.20f;
    public int attackMinFrames = 3;

    // ---- static-image replay (F3) ---------------------------------------------------------------------------------------
    /** Eligible frames from this many ms before "now" are assessed for temporal variation. */
    public long staticWindowMs = 5_000;
    public double staticPhotoThreshold = 0.40;   // [SIM]-derived event threshold; see StaticReplayDetector
    public int staticMinPairs = 10;
    public int staticMinVaryingPairs = 1;

    // ---- temporal binding (T1.2) ---------------------------------------------------------------------------------------
    /** Device sensor-to-host latency allowance before the RCAPTURE request (to be replaced by the flash-rig measurement). */
    public long windowLatencyMs = 300;
    public int windowMinFrames = 3;
    public long windowMaxGapMs = 500;
    public int windowMinEmbeddings = 1;
    /** Every frontal embedding of the attempt must match the capture at least this well (SFace stand-in). */
    public float subjectMinCosine = 0.50f;
    public float frontalMaxAbsYaw = 0.25f;

    // ---- clocks, device trust -------------------------------------------------------------------------------------------
    public long clockJumpToleranceMs = 2_000;
    /**
     * Required device certification for this workflow: null (any), "L0" or "L1" (exact, case-sensitive). Any other value
     * is a configuration error ({@link #validate()}). Proposed: L1 for operator/supervisor (owner decision).
     */
    public String requiredCertification = null;
    /** A frame tagged with a caller-supplied receipt time older than this is rejected (see LivenessSession#tagArrival). */
    public long maxArrivalAgeMs = 1_000;

    // ---- capture-window scene swap (finding 3) ----------------------------------------------------------------------
    /**
     * PROPOSED, default off (owner decision): also require at least one varying frame pair (static detector) inside the
     * capture window itself. Detects a stream switched to a still only during RCAPTURE, at the cost of genuine retries
     * when the user does not blink/move during the capture (cost measured on [SIM] data only).
     */
    public boolean requireVariationInCaptureWindow = false;
    /** Minimum consecutive eligible pairs inside the capture window for that rule. */
    public int captureWindowMinPairs = 5;

    // ---- evidence store bounds ------------------------------------------------------------------------------------------
    public int maxRecords = 2_000;
    public long maxRecordAgeMs = 60_000;
    /**
     * Attempt-level subject ledger bound: frontal embeddings kept for the WHOLE attempt, independent of record eviction.
     * Reaching it fails the attempt closed (never evicts).
     */
    public int maxAttemptEmbeddings = 2_000;
    /** Device faults (per session, or persisted per subject) at which the outcome is flagged for device diagnosis. */
    public int deviceFaultFlagThreshold = 2;

    // ---- B1 stream authentication PROTOTYPE (docs/phase1/B1_STREAM_DIGEST_DESIGN.md) -------------------------------
    /**
     * Require device-signed stream evidence (B1 prototype). Default false: stream evidence is UNAUTHENTICATED and every
     * outcome says so ({@code SessionOutcome.streamAuthenticated == false}). Requires a {@code StreamAuthenticator}.
     */
    public boolean requireStreamAuthentication = false;
    /** Trailing uncovered evidence frames that may be excluded from the decision (emitted after signing). */
    public int b1MaxUncoveredTail = 2;
    /** Signed frames inside the capture window the client may not have received. Provisional. */
    public int b1MaxMissingInWindow = 2;
    /** Statement issuedAt tolerance around the capture window (mirrors captureWindowSkew). Provisional. */
    public long b1StatementSkewMs = 5_000;
    /** Attempt-level received-frame log bound; overflow fails closed. */
    public int maxAttemptFrames = 4_000;

    /** A deep copy: a session pins its policy at construction (later mutation of the caller's object has no effect). */
    public SessionPolicy copy() {
        SessionPolicy c = new SessionPolicy();
        for (java.lang.reflect.Field f : SessionPolicy.class.getFields()) {
            if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                try {
                    f.set(c, f.get(this));
                } catch (IllegalAccessException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        return c;
    }

    /** @throws IllegalArgumentException on any invalid or unsafe combination; the session refuses to be created. */
    public void validate() {
        check(requiredCertification == null || "L0".equals(requiredCertification) || "L1".equals(requiredCertification),
                "requiredCertification must be null, \"L0\" or \"L1\": " + requiredCertification);
        check(maxAttempts >= 1 && maxAttackEvents >= 0 && maxDeviceRecoveries >= 0 && maxChannelEvents >= 0, "attempt limits");
        check(collectTimeoutMs > 0 && readyTimeoutMs > 0 && captureTimeoutMs > 0 && sessionTtlMs > 0, "timeouts must be > 0");
        check(passiveWindowMs > 0 && passiveMinFrames >= 2 && passiveMinSpanMs >= 0 && attackMinFrames >= 1, "passive window");
        check(prob(streamAccept) && prob(streamAttack) && streamAttack < streamAccept, "stream thresholds: 0 <= attack < accept <= 1");
        check(staticWindowMs > 0 && staticPhotoThreshold > 0 && staticMinPairs >= 1 && staticMinVaryingPairs >= 1, "static detector");
        check(windowLatencyMs >= 0 && windowMinFrames >= 1 && windowMaxGapMs > 0 && windowMinEmbeddings >= 1, "capture window");
        check(subjectMinCosine > 0f && subjectMinCosine <= 1f && frontalMaxAbsYaw > 0f, "subject consistency");
        check(clockJumpToleranceMs > 0 && maxArrivalAgeMs > 0, "clock tolerances");
        check(captureWindowMinPairs >= 1, "captureWindowMinPairs");
        check(b1MaxUncoveredTail >= 0 && b1MaxMissingInWindow >= 0 && b1StatementSkewMs >= 0 && maxAttemptFrames >= 1, "B1 bounds");
        check(maxRecords >= 2 * passiveMinFrames && maxAttemptEmbeddings >= 1, "store bounds");
        check(deviceFaultFlagThreshold >= 1, "deviceFaultFlagThreshold");
        // The engine converts these to nanoseconds (x 1,000,000). Bound them so that arithmetic cannot overflow into a
        // negative window; 24 h is far beyond any sensible setting (record age: 48 h so it can outlive a 24 h window).
        long[] ms = {collectTimeoutMs, readyTimeoutMs, captureTimeoutMs, sessionTtlMs, passiveWindowMs, passiveMinSpanMs,
                staticWindowMs, windowLatencyMs, windowMaxGapMs, clockJumpToleranceMs, maxArrivalAgeMs, b1StatementSkewMs};
        for (long v : ms) {
            check(v <= MAX_MS, "millisecond limits must be <= 24 h (" + v + ")");
        }
        check(maxRecordAgeMs <= 2 * MAX_MS, "maxRecordAgeMs must be <= 48 h (" + maxRecordAgeMs + ")");
        // Records needed by a decision must not be evicted by age while they are still needed (fail-closed anyway).
        check(maxRecordAgeMs > Math.max(staticWindowMs, passiveWindowMs) && maxRecordAgeMs > captureTimeoutMs + windowLatencyMs,
                "maxRecordAgeMs must exceed the static/passive windows and captureTimeoutMs + windowLatencyMs");
    }

    private static boolean prob(float v) {
        return Float.isFinite(v) && v >= 0f && v <= 1f;
    }

    private static void check(boolean ok, String what) {
        if (!ok) {
            throw new IllegalArgumentException("invalid SessionPolicy: " + what);
        }
    }
}
