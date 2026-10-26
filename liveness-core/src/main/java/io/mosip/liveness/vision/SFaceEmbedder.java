package io.mosip.liveness.vision;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

import java.nio.FloatBuffer;
import java.util.Collections;

/**
 * SFace (OpenCV zoo, Apache-2.0) 128-d face embedding, used <em>only</em> for capture-to-stream subject
 * consistency in {@code CaptureBinder}. It is not the MOSIP matcher and makes no identity decision.
 */
public final class SFaceEmbedder implements AutoCloseable {
    /** ArcFace 5-point template at 112x112 (as in OpenCV FaceRecognizerSF::alignCrop). */
    public static final float[][] TEMPLATE = {
        {38.2946f, 51.6963f}, {73.5318f, 51.5014f}, {56.0252f, 71.7366f}, {41.5493f, 92.3655f}, {70.7299f, 92.2041f}
    };
    private final OrtSession session;
    private final float[] buf = new float[3 * 112 * 112];

    public SFaceEmbedder(OrtSession session) {
        this.session = session;
    }

    /** Synchronized because the aligned-crop buffer is shared state. */
    public synchronized float[] embed(BgrImage img, Face face) throws OrtException {
        double[] m = ImageOps.similarityTransform(face.landmarks, TEMPLATE);
        ImageOps.warpAffineToChw(img, m, 112, 112, buf);
        try (OnnxTensor in = OnnxTensor.createTensor(OrtModels.env(), FloatBuffer.wrap(buf), new long[] {1, 3, 112, 112});
             OrtSession.Result r = session.run(Collections.singletonMap("data", in))) {
            float[] v = ((float[][]) r.get(0).getValue())[0];
            double n = 0;
            for (float x : v) {
                if (!Float.isFinite(x)) {
                    throw new IllegalStateException("non-finite embedding");
                }
                n += x * x;
            }
            n = Math.sqrt(n) + 1e-12;
            float[] out = new float[v.length];
            for (int i = 0; i < v.length; i++) {
                out[i] = (float) (v[i] / n);
            }
            return out;
        }
    }

    public static float cosine(float[] a, float[] b) {
        double s = 0;
        for (int i = 0; i < a.length; i++) {
            s += a[i] * b[i];
        }
        return (float) s;
    }

    @Override
    public void close() throws OrtException {
        session.close();
    }
}
