package io.mosip.liveness.streamauth;

import java.util.Collections;
import java.util.Set;

/**
 * Result of verifying B1 stream evidence. {@code PROTOCOL_FAILURE} and {@code INTEGRITY_FAILURE} are authentication
 * failures, <b>not</b> attack or PAD verdicts (design §8).
 */
public final class StreamAuthResult {
    public enum Outcome { AUTHENTICATED, PROTOCOL_FAILURE, INTEGRITY_FAILURE }

    public enum Reason {
        OK,
        // protocol failures
        STATEMENT_MISSING, MALFORMED, SEQUENCE_GAP, SEQUENCE_REORDER, CHAIN_MISMATCH, MISSING_FRAMES_IN_WINDOW, STALE_STATEMENT,
        /** Covered frames received in the capture window carry device times outside it (delayed/time-shifted stream). */
        STALE_FRAMES,
        // integrity failures
        BAD_SIGNATURE, UNTRUSTED_SIGNER, SIGNER_NOT_CAPTURE_DEVICE, WRONG_TRANSACTION, WRONG_DEVICE,
        CAPTURE_NOT_BOUND, FRAME_NOT_COVERED, FRAME_REORDERED, UNHASHED_FRAME;

        public Outcome outcome() {
            switch (this) {
                case OK:
                    return Outcome.AUTHENTICATED;
                case STATEMENT_MISSING: case MALFORMED: case SEQUENCE_GAP: case SEQUENCE_REORDER: case CHAIN_MISMATCH:
                case MISSING_FRAMES_IN_WINDOW: case STALE_STATEMENT: case STALE_FRAMES:
                    return Outcome.PROTOCOL_FAILURE;
                default:
                    return Outcome.INTEGRITY_FAILURE;
            }
        }
    }

    public final Outcome outcome;
    public final Reason reason;
    public final String detail;
    /** Tag sequence numbers of received frames matched to a signed entry. */
    public final Set<Long> coveredTags;
    /** Trailing uncovered evidence frames excluded from the decision (design §6 rule 3). */
    public final Set<Long> excludedTailTags;
    public final int statementEntries;
    public final int missingInWindow;

    StreamAuthResult(Reason reason, String detail, Set<Long> covered, Set<Long> excluded, int entries, int missing) {
        this.outcome = reason.outcome();
        this.reason = reason;
        this.detail = detail;
        this.coveredTags = Collections.unmodifiableSet(covered);
        this.excludedTailTags = Collections.unmodifiableSet(excluded);
        this.statementEntries = entries;
        this.missingInWindow = missing;
    }

    static StreamAuthResult fail(Reason r, String detail) {
        return new StreamAuthResult(r, detail, Collections.emptySet(), Collections.emptySet(), 0, 0);
    }

    @Override
    public String toString() {
        return outcome + "/" + reason + (detail == null ? "" : " " + detail);
    }
}
