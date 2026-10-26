package io.mosip.liveness.session;

/**
 * One accepted piece of per-frame evidence on the session timeline. Holds no image; the aligned grey crop and landmarks
 * are kept in memory for static-replay detection only and are discarded with the session.
 */
public final class EvidenceRecord {
    public final long epoch;
    public final long seq;
    public final long monoNanos;
    public final long wallMillis;
    public final int faceCount;           // -1 = frozen (not decoded)
    public final boolean eligible;
    public final String ineligibleReason;
    public final Float pad;               // P(real) for eligible frames, else null
    public final float[][] landmarks;     // null unless exactly one face
    public final float[] faceBox;         // null unless exactly one face
    public final float[] alignedGrey;     // null unless eligible
    public final float yawProxy;
    /** Set later, when the asynchronous embedding for this frame arrives (memory only). */
    volatile float[] embedding;
    /**
     * Cached static-replay residuals to the previous usable record of the same epoch, identified by its sequence number
     * (a seq, not a reference: references would chain evicted records and defeat the bounded store). NaN = not cached.
     */
    long residualPrevSeq = Long.MIN_VALUE;
    double geomToPrev = Double.NaN;
    double photoToPrev = Double.NaN;

    public EvidenceRecord(long epoch, long seq, long monoNanos, long wallMillis, int faceCount, boolean eligible,
                          String ineligibleReason, Float pad, float[][] landmarks, float[] faceBox, float[] alignedGrey,
                          float yawProxy) {
        this.epoch = epoch;
        this.seq = seq;
        this.monoNanos = monoNanos;
        this.wallMillis = wallMillis;
        this.faceCount = faceCount;
        this.eligible = eligible;
        this.ineligibleReason = ineligibleReason;
        this.pad = pad;
        this.landmarks = landmarks;
        this.faceBox = faceBox;
        this.alignedGrey = alignedGrey;
        this.yawProxy = yawProxy;
    }

    public float[] embedding() { return embedding; }

    public boolean frozen() { return "FROZEN_FRAME".equals(ineligibleReason); }

    public boolean frontal(float maxAbsYaw) { return !Float.isNaN(yawProxy) && Math.abs(yawProxy) <= maxAbsYaw; }
}
