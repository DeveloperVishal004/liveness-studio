package io.mosip.liveness.pipeline;

import io.mosip.liveness.frame.EncodedFrame;
import io.mosip.liveness.vision.BgrImage;
import io.mosip.liveness.vision.Face;
import io.mosip.liveness.vision.ImageDecoder;
import io.mosip.liveness.vision.ImageOps;
import io.mosip.liveness.vision.MiniFasPad;
import io.mosip.liveness.vision.Phase0Models;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The per-frame passive path: decode -> detect (or reuse track) -> quality -> PAD -> (optional) embedding.
 * Single-threaded by design (one inference worker); every stage is timed separately (architecture section 7.1).
 *
 * <p>Phase-0 scope: produces per-frame evidence and timings. Aggregation and the decision state machine are out of
 * scope until model selection; nothing here accepts or rejects a person.
 */
public final class FramePipeline implements AutoCloseable {

    public static final class Config {
        /** Run the detector every k-th frame and reuse the last box in between (k=1: detect every frame). */
        public int detectEvery = 1;
        /** Compute an embedding every k-th eligible frame (0 = never). */
        public int embedEvery = 5;
        /** Compute embeddings on a background thread (default) instead of inline on the critical path. */
        public boolean asyncEmbedding = true;
        /** Minimum face height in pixels for a frame to be PAD-eligible. */
        public int minFaceHeightPx = 80;
        public double minMeanGrey = 40;
        public double maxMeanGrey = 220;
        public double minSharpness = 15;
    }

    /** Evidence for one frame. Holds no pixels; the embedding is kept in memory only (never logged). */
    public static final class FrameEvidence {
        public final long seq;
        public final long receivedNanos;
        public final int faceCount;
        public final boolean detectorRan;
        public final boolean eligible;
        public final String ineligibleReason;
        public final float faceHeightPx;
        public final double meanGrey;
        public final double sharpness;
        public final Float padFused;
        public final float[] embedding;
        public final Map<String, Long> spans;
        public final int width;
        public final int height;
        /** 5 landmarks of the single face (null unless exactly one face). Memory only. */
        public float[][] landmarks;
        /** x, y, w, h of the single face (null unless exactly one face). */
        public float[] faceBox;
        /** 64x64 landmark-aligned grey crop for static-replay detection (null unless eligible). Memory only, never logged. */
        public float[] alignedGrey;
        /** Yaw proxy: (nose.x - eye-midpoint.x) / inter-ocular distance; NaN unless exactly one face. */
        public float yawProxy = Float.NaN;

        FrameEvidence(long seq, long receivedNanos, int faceCount, boolean detectorRan, boolean eligible, String why,
                      float faceH, double grey, double sharp, Float pad, float[] emb, Map<String, Long> spans, int w, int h) {
            this.seq = seq;
            this.receivedNanos = receivedNanos;
            this.faceCount = faceCount;
            this.detectorRan = detectorRan;
            this.eligible = eligible;
            this.ineligibleReason = why;
            this.faceHeightPx = faceH;
            this.meanGrey = grey;
            this.sharpness = sharp;
            this.padFused = pad;
            this.embedding = emb;
            this.spans = spans;
            this.width = w;
            this.height = h;
        }
    }

    private final Phase0Models models;
    private final Config cfg;
    private final ImageDecoder decoder = new ImageDecoder();
    private List<Face> lastFaces = Collections.emptyList();
    private long processed;
    private long eligibleCount;
    private byte[] lastFrameBytes;
    private int lastFrameHash;
    private long frozenCount;
    private final EmbeddingSampler sampler;
    private volatile EmbeddingSampler.Listener embeddingListener;
    private final float[] alignBuf = new float[3 * ALIGN * ALIGN];
    static final int ALIGN = 64;
    private static final float[][] TEMPLATE48 = scaledTemplate(ALIGN / 112f);
    private final java.util.ArrayDeque<float[]> inlineRecent = new java.util.ArrayDeque<>();

    public FramePipeline(Phase0Models models, Config cfg) {
        this.models = models;
        this.cfg = cfg;
        this.sampler = cfg.embedEvery > 0 && cfg.asyncEmbedding ? new EmbeddingSampler(models.embedder, 32) : null;
    }

    private static float[][] scaledTemplate(float k) {
        float[][] t = new float[5][2];
        for (int i = 0; i < 5; i++) {
            t[i][0] = io.mosip.liveness.vision.SFaceEmbedder.TEMPLATE[i][0] * k;
            t[i][1] = io.mosip.liveness.vision.SFaceEmbedder.TEMPLATE[i][1] * k;
        }
        return t;
    }

    /**
     * Receives every embedding with the attachment given to {@link #process(EncodedFrame, Object)} (the session's frame
     * tag) and the frame's monotonic arrival time. Set before frames are processed.
     */
    public void setEmbeddingListener(EmbeddingSampler.Listener l) {
        this.embeddingListener = l;
        if (sampler != null) {
            sampler.setListener(l);
        }
    }

    /** Number of byte-identical repeated frames rejected as FROZEN_FRAME. */
    public long frozenFrames() { return frozenCount; }

    /** Most recent subject embeddings from eligible frames (for capture binding); memory only. */
    public List<float[]> recentEmbeddings(int n) {
        if (sampler != null) {
            return sampler.recent(n);
        }
        synchronized (inlineRecent) {
            List<float[]> all = new java.util.ArrayList<>(inlineRecent);
            return all.subList(Math.max(0, all.size() - n), all.size());
        }
    }

    @Override
    public void close() {
        if (sampler != null) {
            sampler.close();
        }
        synchronized (inlineRecent) {
            inlineRecent.clear();
        }
    }

    public FrameEvidence process(EncodedFrame frame) throws Exception {
        return process(frame, null);
    }

    /**
     * @param attachment opaque value (e.g. the session frame tag) passed back with the frame's embedding, so late
     *                   embeddings can be checked against the session/epoch the frame arrived in
     */
    public FrameEvidence process(EncodedFrame frame, Object attachment) throws Exception {
        Map<String, Long> spans = new LinkedHashMap<>();
        long t = System.nanoTime();
        // A byte-identical repeat of the previous frame means a frozen sensor/MDS or a looped injection: it is never
        // evidence (Phase-0 R11; real sensors always carry noise, so consecutive encoded frames differ).
        byte[] bytes = frame.data();
        int h = java.util.Arrays.hashCode(bytes);
        boolean frozen = lastFrameBytes != null && h == lastFrameHash && java.util.Arrays.equals(bytes, lastFrameBytes);
        lastFrameHash = h;
        lastFrameBytes = bytes;
        if (frozen) {
            frozenCount++;
            spans.put("total", System.nanoTime() - t);
            return new FrameEvidence(frame.seq(), frame.receivedNanos(), -1, false, false, "FROZEN_FRAME", 0, 0, 0,
                    null, null, spans, 0, 0);
        }
        BgrImage img = decoder.decode(bytes);
        long t1 = System.nanoTime();
        spans.put("decode", t1 - t);

        boolean runDetector = cfg.detectEvery <= 1 || processed % cfg.detectEvery == 0 || lastFaces.size() != 1;
        List<Face> faces = runDetector ? models.detector.detect(img) : lastFaces;
        long t2 = System.nanoTime();
        spans.put(runDetector ? "detect" : "track_reuse", t2 - t1);
        lastFaces = faces;
        processed++;

        if (faces.size() != 1) {
            spans.put("total", t2 - t);
            return new FrameEvidence(frame.seq(), frame.receivedNanos(), faces.size(), runDetector, false,
                    faces.isEmpty() ? "NO_FACE" : "MULTIPLE_FACES", 0, 0, 0, null, null, spans, img.width, img.height);
        }
        Face f = faces.get(0);
        int x0 = (int) f.x, y0 = (int) f.y, x1 = (int) (f.x + f.w), y1 = (int) (f.y + f.h);
        double grey = ImageOps.meanGrey(img, x0, y0, x1, y1);
        double sharp = ImageOps.laplacianVariance(img, x0, y0, x1, y1);
        long t3 = System.nanoTime();
        spans.put("quality", t3 - t2);
        String why = null;
        if (f.h < cfg.minFaceHeightPx) {
            why = "FACE_TOO_SMALL";
        } else if (grey < cfg.minMeanGrey) {
            why = "TOO_DARK";
        } else if (grey > cfg.maxMeanGrey) {
            why = "TOO_BRIGHT";
        } else if (sharp < cfg.minSharpness) {
            why = "BLUR";
        }
        if (why != null) {
            spans.put("total", t3 - t);
            FrameEvidence ev = new FrameEvidence(frame.seq(), frame.receivedNanos(), 1, runDetector, false, why, f.h, grey,
                    sharp, null, null, spans, img.width, img.height);
            describeFace(ev, f, null);
            return ev;
        }
        float pad = MiniFasPad.fuse(models.pad.score(img, f));
        long t4 = System.nanoTime();
        spans.put("pad", t4 - t3);
        float[] emb = null;
        if (cfg.embedEvery > 0 && eligibleCount % cfg.embedEvery == 0) {
            if (sampler != null) {
                sampler.offer(frame.seq(), frame.receivedNanos(), img, f, attachment);   // off the critical path
            } else {
                emb = models.embedder.embed(img, f);         // inline (benchmark comparison only)
                spans.put("embed", System.nanoTime() - t4);
                EmbeddingSampler.Listener l = embeddingListener;
                if (l != null) {
                    l.onEmbedding(frame.seq(), frame.receivedNanos(), emb, attachment);
                }
                synchronized (inlineRecent) {
                    inlineRecent.addLast(emb);
                    while (inlineRecent.size() > 32) {
                        inlineRecent.removeFirst();
                    }
                }
            }
        }
        eligibleCount++;
        long t5 = System.nanoTime();
        FrameEvidence ev = new FrameEvidence(frame.seq(), frame.receivedNanos(), 1, runDetector, true, null, f.h, grey,
                sharp, pad, emb, spans, img.width, img.height);
        describeFace(ev, f, img);
        spans.put("motion_signature", System.nanoTime() - t5);
        spans.put("total", System.nanoTime() - t);
        return ev;
    }

    /** Landmarks, box, yaw proxy; plus the aligned grey crop when {@code img} is given (eligible frames). */
    private void describeFace(FrameEvidence ev, Face f, BgrImage img) {
        float[][] lm = new float[5][2];
        for (int i = 0; i < 5; i++) {
            lm[i][0] = f.landmarks[i][0];
            lm[i][1] = f.landmarks[i][1];
        }
        ev.landmarks = lm;
        ev.faceBox = new float[] {f.x, f.y, f.w, f.h};
        float iod = (float) Math.hypot(lm[1][0] - lm[0][0], lm[1][1] - lm[0][1]);
        ev.yawProxy = iod > 1e-3f ? (lm[2][0] - (lm[0][0] + lm[1][0]) / 2f) / iod : Float.NaN;
        if (img != null) {
            double[] m = ImageOps.similarityTransform(lm, TEMPLATE48);
            ImageOps.warpAffineToChw(img, m, ALIGN, ALIGN, alignBuf);
            int plane = ALIGN * ALIGN;
            float[] g = new float[plane];
            for (int i = 0; i < plane; i++) {
                g[i] = 0.114f * alignBuf[i] + 0.587f * alignBuf[i + plane] + 0.299f * alignBuf[i + 2 * plane];
            }
            ev.alignedGrey = g;
        }
    }
}
