package io.mosip.liveness.frame;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Decides whether an asynchronously produced evidence item may still influence the current decision.
 *
 * <p>Implements invariants I5 (fresh frames only) and I6 (stale/expired results never authorize):
 * every item carries the {@code sessionId}, {@code epoch} and frame {@code seq} it was computed for, plus the
 * monotonic receive time of the frame. An item is accepted only if it belongs to the current session and
 * epoch, is strictly newer than the last accepted item, and its frame arrived after the epoch's freshness
 * floor (e.g. challenge issue time + guard). Not thread-safe: owned by the single state-machine thread.
 */
public final class EvidenceGate {
    /** Why an item was rejected; {@code ACCEPTED} otherwise. */
    public enum Verdict { ACCEPTED, WRONG_SESSION, STALE_EPOCH, OUT_OF_ORDER, BEFORE_FRESHNESS_FLOOR, SESSION_CLOSED }

    private static final SecureRandom RNG = new SecureRandom();

    private final byte[] sessionId;
    private long epoch;
    private long lastSeq = Long.MIN_VALUE;
    private long freshnessFloorNanos;
    private boolean floorSet;      // no sentinel value: nanoTime differences must not be compared against MIN_VALUE
    private boolean closed;

    private EvidenceGate(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    /** Opens a gate with a fresh unguessable 128-bit session id. */
    public static EvidenceGate open() {
        byte[] id = new byte[16];
        RNG.nextBytes(id);
        return new EvidenceGate(id);
    }

    /**
     * A gate for another evidence stream of the same session (e.g. asynchronous embeddings): same session id, its own
     * epoch/sequence tracking. Callers must advance both gates' epochs together.
     */
    public static EvidenceGate forSession(byte[] sessionId) {
        if (sessionId == null || sessionId.length != 16) {
            throw new IllegalArgumentException("session id must be 16 bytes");
        }
        return new EvidenceGate(sessionId.clone());
    }

    public byte[] sessionId() { return sessionId.clone(); }
    public long epoch() { return epoch; }

    /**
     * Starts a new epoch (retry, challenge issue, track reset). All evidence computed for earlier epochs is
     * discarded, and frames received before {@code freshnessFloorNanos} are ignored for the new epoch.
     */
    public long advanceEpoch(long freshnessFloorNanos) {
        epoch++;
        lastSeq = Long.MIN_VALUE;
        this.freshnessFloorNanos = freshnessFloorNanos;
        this.floorSet = true;
        return epoch;
    }

    public void close() { closed = true; }

    public Verdict check(byte[] itemSessionId, long itemEpoch, long frameSeq, long frameReceivedNanos) {
        if (closed) {
            return Verdict.SESSION_CLOSED;
        }
        if (!Arrays.equals(sessionId, itemSessionId)) {
            return Verdict.WRONG_SESSION;
        }
        if (itemEpoch != epoch) {
            return Verdict.STALE_EPOCH;
        }
        if (frameSeq <= lastSeq) {
            return Verdict.OUT_OF_ORDER;
        }
        if (floorSet && frameReceivedNanos - freshnessFloorNanos < 0) { // overflow-safe nanoTime comparison
            return Verdict.BEFORE_FRESHNESS_FLOOR;
        }
        lastSeq = frameSeq;
        return Verdict.ACCEPTED;
    }
}
