package io.mosip.liveness.frame;

import java.util.Objects;

/**
 * One compressed frame as received from a face device stream.
 *
 * <p>Timestamps are taken on the host when the last byte of the frame was read: {@code receivedNanos}
 * is {@link System#nanoTime()} (monotonic, used for all freshness decisions) and {@code receivedEpochMillis}
 * is wall-clock time (diagnostics only). SBI STREAM frames carry no device timestamp, so device-side
 * latency is not observable here (see the flash-rig measurement in the probe).
 *
 * <p>The byte array is owned by this object and must not be mutated after construction.
 */
public final class EncodedFrame {
    private final long seq;
    private final long receivedNanos;
    private final long receivedEpochMillis;
    private final String mimeType;
    private final byte[] data;

    public EncodedFrame(long seq, long receivedNanos, long receivedEpochMillis, String mimeType, byte[] data) {
        this.seq = seq;
        this.receivedNanos = receivedNanos;
        this.receivedEpochMillis = receivedEpochMillis;
        this.mimeType = Objects.requireNonNull(mimeType, "mimeType");
        this.data = Objects.requireNonNull(data, "data");
    }

    public long seq() { return seq; }
    public long receivedNanos() { return receivedNanos; }
    public long receivedEpochMillis() { return receivedEpochMillis; }
    public String mimeType() { return mimeType; }
    /** Direct reference to the frame bytes; callers must treat it as read-only. */
    public byte[] data() { return data; }
    public int size() { return data.length; }
}
