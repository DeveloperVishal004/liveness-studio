package io.mosip.liveness.vision;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

import java.nio.FloatBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * YuNet (2023mar) face detector run directly through ONNX Runtime.
 *
 * <p>Decoding is a port of OpenCV {@code FaceDetectorYN} post-processing and is verified against it in the
 * Python reference (IoU 1.0, landmark error &lt; 1e-4 px at equal input size). The frame is downscaled to
 * {@code detWidth} and zero-padded to a multiple of 32 using the dynamic-shape export
 * ({@code models/onnx/yunet_2023mar_dynamic.onnx}).
 */
public final class YuNetDetector implements AutoCloseable {
    private static final int[] STRIDES = {8, 16, 32};

    private final OrtSession session;
    private final int detWidth;
    private final float scoreThreshold;
    private final float nmsThreshold;
    private float[] inputBuf = new float[0];

    public YuNetDetector(OrtSession session, int detWidth, float scoreThreshold, float nmsThreshold) {
        this.session = session;
        this.detWidth = detWidth;
        this.scoreThreshold = scoreThreshold;
        this.nmsThreshold = nmsThreshold;
    }

    /** Synchronized: the reusable input buffer is shared state (stream worker and capture binder may call concurrently). */
    public synchronized List<Face> detect(BgrImage frame) throws OrtException {
        float scale = frame.width > detWidth ? (float) detWidth / frame.width : 1f;
        BgrImage img = frame;
        if (scale != 1f) {
            img = ImageOps.resizeBilinear(frame, Math.round(frame.width * scale), Math.round(frame.height * scale));
        }
        int pw = (img.width + 31) / 32 * 32;
        int ph = (img.height + 31) / 32 * 32;
        int plane = pw * ph;
        if (inputBuf.length != plane * 3) {
            inputBuf = new float[plane * 3];       // reused across frames of equal size
        } else {
            java.util.Arrays.fill(inputBuf, 0f);
        }
        byte[] d = img.data;
        for (int y = 0; y < img.height; y++) {
            int si = y * img.width * 3;
            int di = y * pw;
            for (int x = 0; x < img.width; x++, si += 3, di++) {
                inputBuf[di] = d[si] & 0xFF;
                inputBuf[di + plane] = d[si + 1] & 0xFF;
                inputBuf[di + 2 * plane] = d[si + 2] & 0xFF;
            }
        }
        List<Face> faces = new ArrayList<>();
        try (OnnxTensor in = OnnxTensor.createTensor(OrtModels.env(), FloatBuffer.wrap(inputBuf), new long[] {1, 3, ph, pw});
             OrtSession.Result out = session.run(Collections.singletonMap("input", in))) {
            for (int s : STRIDES) {
                int cols = pw / s;
                float[] cls = flat(out, "cls_" + s);
                float[] obj = flat(out, "obj_" + s);
                float[] bbox = flat(out, "bbox_" + s);
                float[] kps = flat(out, "kps_" + s);
                int n = cls.length;
                if (obj.length != n || bbox.length != 4 * n || kps.length != 10 * n) {
                    throw new IllegalStateException("unexpected YuNet output shapes"); // never guess on bad output
                }
                for (int i = 0; i < n; i++) {
                    float c = clamp01(cls[i]);
                    float o = clamp01(obj[i]);
                    float score = (float) Math.sqrt(c * o);
                    if (!(score >= scoreThreshold)) {
                        continue;
                    }
                    int r = i / cols;
                    int col = i % cols;
                    float cx = (col + bbox[4 * i]) * s;
                    float cy = (r + bbox[4 * i + 1]) * s;
                    float w = (float) Math.exp(bbox[4 * i + 2]) * s;
                    float h = (float) Math.exp(bbox[4 * i + 3]) * s;
                    float[][] lm = new float[5][2];
                    for (int k = 0; k < 5; k++) {
                        lm[k][0] = (kps[10 * i + 2 * k] + col) * s / scale;
                        lm[k][1] = (kps[10 * i + 2 * k + 1] + r) * s / scale;
                    }
                    faces.add(new Face((cx - w / 2) / scale, (cy - h / 2) / scale, w / scale, h / scale, lm, score));
                }
            }
        }
        return nms(faces, nmsThreshold);
    }

    private static float[] flat(OrtSession.Result out, String name) throws OrtException {
        java.util.Optional<ai.onnxruntime.OnnxValue> v = out.get(name);
        if (!v.isPresent()) {
            throw new IllegalStateException("missing YuNet output " + name);
        }
        OnnxTensor t = (OnnxTensor) v.get();
        FloatBuffer fb = t.getFloatBuffer();
        float[] a = new float[fb.remaining()];
        fb.get(a);
        return a;
    }

    static List<Face> nms(List<Face> faces, float thr) {
        faces.sort((a, b) -> Float.compare(b.score, a.score));
        List<Face> keep = new ArrayList<>();
        outer:
        for (Face f : faces) {
            for (Face k : keep) {
                if (f.iou(k) > thr) {
                    continue outer;
                }
            }
            keep.add(f);
        }
        return keep;
    }

    private static float clamp01(float v) {
        return v < 0f ? 0f : (v > 1f ? 1f : v);
    }

    @Override
    public void close() throws OrtException {
        session.close();
    }
}
