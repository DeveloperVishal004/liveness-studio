package io.mosip.liveness.session;

/**
 * Identity of one received frame within a liveness session, assigned <b>at arrival</b> (before any processing).
 *
 * <ul>
 *   <li>{@code monoNanos}: {@link System#nanoTime()} at receipt — the only time used for ordering, freshness and capture
 *       windows. Meaningful only inside this process; never persisted or compared across processes.</li>
 *   <li>{@code wallMillis}: wall clock at receipt — used only to relate device-signed timestamps to the session and for
 *       audit. Never used for ordering (it can jump).</li>
 * </ul>
 */
public final class FrameTag {
    final byte[] sessionId;
    public final long epoch;
    public final long seq;
    public final long monoNanos;
    public final long wallMillis;
    /** SHA-256 of the received frame bytes, computed at receipt (B1); null if tagged without bytes. */
    final byte[] frameSha256;

    FrameTag(byte[] sessionId, long epoch, long seq, long monoNanos, long wallMillis) {
        this(sessionId, epoch, seq, monoNanos, wallMillis, null);
    }

    FrameTag(byte[] sessionId, long epoch, long seq, long monoNanos, long wallMillis, byte[] frameSha256) {
        this.frameSha256 = frameSha256;
        this.sessionId = sessionId;
        this.epoch = epoch;
        this.seq = seq;
        this.monoNanos = monoNanos;
        this.wallMillis = wallMillis;
    }
}
