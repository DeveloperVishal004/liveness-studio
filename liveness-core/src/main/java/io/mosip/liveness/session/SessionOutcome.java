package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;

/** Immutable snapshot of a session's state and counters. Contains no biometric data. */
public final class SessionOutcome {

    public enum State {
        CREATED, CAPTURING, READY_FOR_CAPTURE, CAPTURE_IN_FLIGHT,
        VERIFIED,
        RETRY_PENDING, REJECTED_ATTACK, ERROR_DEVICE,
        FAILED_MAX_RETRIES, FAILED_POLICY, ERROR_ENGINE, CANCELLED, EXPIRED, SHUTDOWN;

        public boolean terminal() {
            return this == VERIFIED || this == FAILED_MAX_RETRIES || this == FAILED_POLICY || this == ERROR_ENGINE
                    || this == CANCELLED || this == EXPIRED || this == SHUTDOWN;
        }
    }

    public enum Reason {
        NONE, OK,
        // passive phase
        INSUFFICIENT_EVIDENCE, STATIC_REPLAY_SUSPECT, PASSIVE_UNCERTAIN_NO_CHALLENGE, MULTIPLE_FACES, STREAM_PAD_ATTACK,
        CAPTURE_NOT_STARTED,
        // capture / binding
        CAPTURE_TIMEOUT, BINDING_REJECTED, BINDING_INTEGRITY, CAPTURE_PAD_ATTACK, CAPTURE_UNCERTAIN,
        // temporal binding
        WINDOW_NOT_COVERED, STREAM_GAP_IN_WINDOW, INTEGRITY_IN_WINDOW, STATIC_IN_WINDOW, WINDOW_PAD_ATTACK,
        WINDOW_PAD_INSUFFICIENT, MISSING_EMBEDDINGS, SUBJECT_CHANGED,
        // environment
        CLOCK_DISCONTINUITY, DEVICE_DISCONNECTED, DEVICE_LEVEL_INSUFFICIENT, ENGINE_ERROR, INVALID_EVIDENCE,
        ATTEMPT_EVIDENCE_OVERFLOW, STATIC_IN_CAPTURE_WINDOW,
        // B1 prototype: authentication failures, NOT attack verdicts
        STREAM_AUTH_PROTOCOL_FAILURE, STREAM_AUTH_INTEGRITY_FAILURE,
        /** Authenticated, device-bound response that is non-conforming (no nonce, malformed content, clock outside the
         *  window): rejected, never evidence, no attack event; the next attempt consumes the attempt cap. */
        DEVICE_FAULT,
        /** Response that cannot be attributed to the subject (unauthenticated or unbound): rejected security event
         *  counted against the capture CHANNEL, not the subject (owner decision 2026-10-24). */
        CHANNEL_INTEGRITY,
        /** The channel exceeded its integrity-event limit: no capture on it until an administrative reset. */
        CHANNEL_INTEGRITY_LOCKED,
        /** The attempt ledger could not be authenticated (tampered/unreadable): no session may start. */
        LEDGER_UNTRUSTED,
        // limits / lifecycle
        MAX_RETRIES, ATTACK_LIMIT, DEVICE_RECOVERY_LIMIT, SESSION_EXPIRED, CANCELLED, SHUTDOWN
    }

    public final State state;
    public final Reason reason;
    public final BindingResult.Reason bindingReason;
    public final int attempt;
    public final int attackEvents;
    /** SHA-256 of the bound signed capture; non-null only when VERIFIED (invariant I10). */
    public final String verifiedCaptureSha256;
    public final long droppedStaleFrames;
    public final long droppedStaleEmbeddings;
    public final long invalidEvidence;
    public final long ignoredLateResponses;
    /** Caller-supplied arrival timestamps rejected as future, stale, non-monotonic or wall/mono-inconsistent. */
    public final long rejectedArrivalTimestamps;
    /**
     * True only if B1 verified the stream evidence of the VERIFIED attempt. False means the stream evidence is
     * UNAUTHENTICATED (the default mode), whatever the state.
     */
    public final boolean streamAuthenticated;
    /** Last B1 verifier result (e.g. "INTEGRITY_FAILURE/FRAME_NOT_COVERED"), or null if not run. */
    public final String streamAuthResult;
    /** Device faults in this session (DEVICE_FAULT, device error, bad bio format); diagnostic only. */
    public final int deviceFaults;
    /** Repeated device faults (this session or persisted for this subject): flag the device for diagnosis. */
    public final boolean deviceFaultFlag;
    /** Channel-integrity events recorded for this session's capture channel (persisted; administrative reset only). */
    public final int channelEvents;
    /** The capture channel is locked (over maxChannelEvents): fail closed until an administrative reset. */
    public final boolean channelLocked;
    public final String detail;

    SessionOutcome(State state, Reason reason, BindingResult.Reason bindingReason, int attempt, int attackEvents,
                   String verifiedHash, long staleFrames, long staleEmb, long invalid, long late, long rejectedTs, boolean streamAuthenticated,
                   String streamAuthResult, int deviceFaults, boolean deviceFaultFlag, int channelEvents,
                   boolean channelLocked, String detail) {
        this.channelEvents = channelEvents;
        this.channelLocked = channelLocked;
        this.deviceFaults = deviceFaults;
        this.deviceFaultFlag = deviceFaultFlag;
        this.streamAuthenticated = streamAuthenticated;
        this.streamAuthResult = streamAuthResult;
        this.state = state;
        this.reason = reason;
        this.bindingReason = bindingReason;
        this.attempt = attempt;
        this.attackEvents = attackEvents;
        this.verifiedCaptureSha256 = verifiedHash;
        this.droppedStaleFrames = staleFrames;
        this.droppedStaleEmbeddings = staleEmb;
        this.invalidEvidence = invalid;
        this.ignoredLateResponses = late;
        this.rejectedArrivalTimestamps = rejectedTs;
        this.detail = detail;
    }

    @Override
    public String toString() {
        return state + "/" + reason + (bindingReason == null ? "" : "(" + bindingReason + ")") + " attempt=" + attempt
                + " attacks=" + attackEvents + (streamAuthResult == null ? "" : " b1=" + streamAuthResult)
                + (deviceFaults == 0 ? "" : " deviceFaults=" + deviceFaults + (deviceFaultFlag ? "(flagged)" : ""))
                + (channelEvents == 0 ? "" : " channelEvents=" + channelEvents + (channelLocked ? "(LOCKED)" : ""))
                + (detail == null ? "" : " " + detail);
    }
}
