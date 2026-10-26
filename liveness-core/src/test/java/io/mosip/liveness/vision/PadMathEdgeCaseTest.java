package io.mosip.liveness.vision;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Extreme-value tests for the PAD arithmetic and crop geometry (no model files needed). [CODE]
 * A PAD score is security-relevant: it must stay in [0,1] and be finite whatever the model emits, and the crop must
 * never leave the image whatever the detector reports.
 */
class PadMathEdgeCaseTest {
    private static float p(float a, float b, float c) throws Exception {
        return MiniFasPad.validatedRealProbability(new float[][] {{a, b, c}});
    }

    @Test
    void probabilityIsStableForExtremeLogits() throws Exception {
        assertEquals(1f / 3f, p(0, 0, 0), 1e-6);
        assertEquals(0f, p(1e30f, 0, 0), 0f);                       // no overflow: max-subtracted softmax
        assertEquals(1f, p(-1e30f, 1e30f, -1e30f), 0f);
        assertEquals(1f, p(0, 1000f, 0), 1e-6);
        assertEquals(0f, p(0, -1000f, 0), 1e-6);
        assertEquals(1f, p(Float.NEGATIVE_INFINITY, 5f, Float.NEGATIVE_INFINITY), 0f);   // -inf class = probability 0
        assertEquals(0f, p(5f, Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY), 0f);
        assertEquals(0f, p(Float.MAX_VALUE, -Float.MAX_VALUE, 0), 0f);
        assertEquals(1f, p(-Float.MAX_VALUE, Float.MAX_VALUE, -Float.MAX_VALUE), 0f);
        assertEquals(0.5f, p(7f, 7f, -1e30f), 1e-6);
    }

    @Test
    void nonFiniteOrMalformedModelOutputIsRejectedNeverScored() {
        float nan = Float.NaN, inf = Float.POSITIVE_INFINITY, ninf = Float.NEGATIVE_INFINITY;
        for (float[] bad : new float[][] {{nan, 0, 0}, {0, nan, 0}, {0, 0, nan}, {inf, 0, 0}, {0, inf, 0}, {0, 0, inf},
                {ninf, ninf, ninf}, {nan, nan, nan}, {inf, inf, inf}}) {
            assertThrows(MiniFasPad.PadOutputException.class,
                    () -> MiniFasPad.validatedRealProbability(new float[][] {bad}), java.util.Arrays.toString(bad));
        }
        assertThrows(MiniFasPad.PadOutputException.class, () -> MiniFasPad.validatedRealProbability(null));
        assertThrows(MiniFasPad.PadOutputException.class, () -> MiniFasPad.validatedRealProbability(new float[0][]));
        assertThrows(MiniFasPad.PadOutputException.class, () -> MiniFasPad.validatedRealProbability(new float[][] {{}}));
        assertThrows(MiniFasPad.PadOutputException.class, () -> MiniFasPad.validatedRealProbability(new float[][] {{1, 2}}));
        assertThrows(MiniFasPad.PadOutputException.class, () -> MiniFasPad.validatedRealProbability(new float[][] {{1, 2, 3, 4}}));
        assertThrows(MiniFasPad.PadOutputException.class,
                () -> MiniFasPad.validatedRealProbability(new float[][] {{1, 2, 3}, {1, 2, 3}}));     // batch of 2
    }

    @Test
    void probabilityIsAlwaysInUnitRangeAndMonotonicInTheRealLogit() throws Exception {
        Random r = new Random(11);
        for (int i = 0; i < 20_000; i++) {
            float scale = (float) Math.pow(10, r.nextInt(12) - 3);           // 1e-3 .. 1e8
            float a = (float) r.nextGaussian() * scale, b = (float) r.nextGaussian() * scale, c = (float) r.nextGaussian() * scale;
            float lo = p(a, b, c);
            assertTrue(lo >= 0f && lo <= 1f && Float.isFinite(lo), lo + " for " + a + "," + b + "," + c);
            float hi = p(a, b + Math.abs(scale), c);                         // a larger "real" logit never lowers P(real)
            assertTrue(hi >= lo, hi + " < " + lo);
        }
    }

    @Test
    void fusionIsTheMeanAndAnEmptyMapIsNaNNeverAPassingScore() {
        Map<Float, Float> one = Collections.singletonMap(2.7f, 0.9f);
        assertEquals(0.9f, MiniFasPad.fuse(one), 0f);
        Map<Float, Float> two = new LinkedHashMap<>();
        two.put(2.7f, 1.0f);
        two.put(4.0f, 0.0f);
        assertEquals(0.5f, MiniFasPad.fuse(two), 0f);
        // one model failing high and one low does not average into a pass
        two.put(4.0f, 0.2f);
        assertTrue(MiniFasPad.fuse(two) < 0.80f);
        float empty = MiniFasPad.fuse(new LinkedHashMap<>());
        assertTrue(Float.isNaN(empty), "no scores must not become a number: " + empty);   // the session drops NaN as invalid evidence
        assertTrue(!(empty >= 0.80f) && !(empty < 0.20f), "NaN satisfies neither gate");
    }

    @Test
    void cropBoxNeverLeavesTheImageForAnyDetectorOutput() {
        Random r = new Random(5);
        float[][] lm = new float[5][2];
        for (int i = 0; i < 60_000; i++) {
            int srcW = 2 + r.nextInt(4000), srcH = 2 + r.nextInt(4000);
            float x = (r.nextFloat() - 0.5f) * 20_000f, y = (r.nextFloat() - 0.5f) * 20_000f;     // far outside the image too
            float w = 1 + r.nextFloat() * 10_000f, h = 1 + r.nextFloat() * 10_000f;
            float scale = r.nextBoolean() ? 2.7f : 4.0f;
            int[] b = MiniFasPad.cropBox(srcW, srcH, new Face(x, y, w, h, lm, 0.9f), scale);
            String ctx = srcW + "x" + srcH + " face " + x + "," + y + "," + w + "," + h + " -> " + java.util.Arrays.toString(b);
            assertTrue(b[0] >= 0 && b[1] >= 0 && b[2] <= srcW - 1 && b[3] <= srcH - 1, ctx);
            assertTrue(b[0] <= b[2] && b[1] <= b[3], ctx);
        }
    }

    @Test
    void emptyOrSubPixelFaceBoxIsRefusedNotCropped() {
        float[][] lm = new float[5][2];
        assertThrows(IllegalArgumentException.class, () -> MiniFasPad.cropBox(640, 480, new Face(10, 10, 0, 50, lm, 0.9f), 2.7f));
        assertThrows(IllegalArgumentException.class, () -> MiniFasPad.cropBox(640, 480, new Face(10, 10, 50, 0, lm, 0.9f), 2.7f));
        assertThrows(IllegalArgumentException.class, () -> MiniFasPad.cropBox(640, 480, new Face(10, 10, 0.9f, 0.9f, lm, 0.9f), 2.7f));
        assertThrows(IllegalArgumentException.class, () -> MiniFasPad.cropBox(640, 480, new Face(10, 10, -5, 50, lm, 0.9f), 2.7f));
        // a face as large as the image is clamped to the image, not rejected
        int[] b = MiniFasPad.cropBox(640, 480, new Face(0, 0, 640, 480, lm, 0.9f), 4.0f);
        assertEquals(0, b[0]);
        assertEquals(0, b[1]);
        assertTrue(b[2] <= 639 && b[3] <= 479);
    }
}
