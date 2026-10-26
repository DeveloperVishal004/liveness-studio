package io.mosip.liveness.vision;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

import java.nio.FloatBuffer;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Stage-1 PAD stand-in: MiniVision MiniFASNet models (Apache-2.0), one per context scale.
 *
 * <p><b>Phase-0 status:</b> used for latency and plumbing only. Its accuracy on MOSIP devices and PAI species is
 * unmeasured; no threshold derived from it is a security claim.
 *
 * <p>Preprocessing reproduces upstream {@code CropImage}: integer bbox, box scaled by {@code scale} about its centre,
 * clamped/shifted into the frame, inclusive crop, resized to 80x80, BGR, raw 0..255 (no normalisation).
 * Output validation implements invariant I2: anything that is not a finite 3-way probability is an error, never a score.
 */
public final class MiniFasPad implements AutoCloseable {
    /** Raised when the model output is unusable; callers must treat this as an engine error (fail closed). */
    public static final class PadOutputException extends Exception {
        PadOutputException(String m) { super(m); }
    }

    private static final int SIZE = 80;
    private final Map<Float, OrtSession> models;
    private final float[] buf = new float[3 * SIZE * SIZE];

    /** @param models scale -> session (e.g. 2.7 -> MiniFASNetV2, 4.0 -> MiniFASNetV1SE) */
    public MiniFasPad(Map<Float, OrtSession> models) {
        this.models = new LinkedHashMap<>(models);
    }

    /** Returns P(real) per scale. Synchronized because the crop buffer is shared state. */
    public synchronized Map<Float, Float> score(BgrImage img, Face face) throws OrtException, PadOutputException {
        Map<Float, Float> out = new LinkedHashMap<>();
        for (Map.Entry<Float, OrtSession> e : models.entrySet()) {
            int[] box = cropBox(img.width, img.height, face, e.getKey());
            ImageOps.cropResizeToChw(img, box[0], box[1], box[2] + 1, box[3] + 1, SIZE, SIZE, buf, 0);
            try (OnnxTensor in = OnnxTensor.createTensor(OrtModels.env(), FloatBuffer.wrap(buf), new long[] {1, 3, SIZE, SIZE});
                 OrtSession.Result r = e.getValue().run(Collections.singletonMap("input", in))) {
                float[][] logits = (float[][]) r.get(0).getValue();
                out.put(e.getKey(), validatedRealProbability(logits));
            }
        }
        return out;
    }

    /** Mean of P(real) across scales (upstream averages the softmax outputs). */
    public static float fuse(Map<Float, Float> perScale) {
        double s = 0;
        for (float v : perScale.values()) {
            s += v;
        }
        return (float) (s / perScale.size());
    }

    static float validatedRealProbability(float[][] logits) throws PadOutputException {
        if (logits == null || logits.length != 1 || logits[0].length != 3) {
            throw new PadOutputException("unexpected PAD output shape");
        }
        float[] l = logits[0];
        float max = Math.max(l[0], Math.max(l[1], l[2]));
        if (!Float.isFinite(max)) {
            throw new PadOutputException("non-finite PAD logits");
        }
        double e0 = Math.exp(l[0] - max), e1 = Math.exp(l[1] - max), e2 = Math.exp(l[2] - max);
        double p = e1 / (e0 + e1 + e2);
        if (!(p >= 0.0 && p <= 1.0)) {
            throw new PadOutputException("PAD probability out of range");
        }
        return (float) p;
    }

    /** Upstream {@code CropImage._get_new_box}; returns inclusive {l, t, r, b}. */
    static int[] cropBox(int srcW, int srcH, Face f, float scale) {
        int x = (int) f.x, y = (int) f.y, bw = (int) f.w, bh = (int) f.h;  // upstream feeds int bboxes
        if (bw <= 0 || bh <= 0) {
            throw new IllegalArgumentException("empty face box");
        }
        double s = Math.min((srcH - 1) / (double) bh, Math.min((srcW - 1) / (double) bw, scale));
        double nw = bw * s, nh = bh * s;
        double cx = bw / 2.0 + x, cy = bh / 2.0 + y;
        double l = cx - nw / 2, t = cy - nh / 2, r = cx + nw / 2, b = cy + nh / 2;
        if (l < 0) { r -= l; l = 0; }
        if (t < 0) { b -= t; t = 0; }
        if (r > srcW - 1) { l -= r - srcW + 1; r = srcW - 1; }
        if (b > srcH - 1) { t -= b - srcH + 1; b = srcH - 1; }
        return new int[] {(int) l, (int) t, (int) r, (int) b};
    }

    @Override
    public void close() throws OrtException {
        for (OrtSession s : models.values()) {
            s.close();
        }
    }
}
