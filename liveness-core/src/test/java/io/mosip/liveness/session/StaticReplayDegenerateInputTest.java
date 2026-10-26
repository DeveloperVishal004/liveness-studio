package io.mosip.liveness.session;

import io.mosip.liveness.session.StaticReplayDetector.Verdict;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Degenerate and extreme inputs to the static-image check (no models needed; synthetic 64x64 crops, [SIM]). The check
 * is a fail-closed gate: anything it cannot positively see as motion must not count as motion, with one documented
 * exception below. [CODE]
 */
class StaticReplayDegenerateInputTest {
    static final SessionPolicy P = new SessionPolicy();
    static final StaticReplayDetector DET = new StaticReplayDetector(P.staticPhotoThreshold, P.staticMinPairs, P.staticMinVaryingPairs);
    static final float[][] LM = {{20, 24}, {44, 24}, {32, 36}, {24, 48}, {40, 48}};

    static float[] texture(long seed) {
        Random r = new Random(seed);
        float[] g = new float[64 * 64];
        for (int i = 0; i < g.length; i++) {
            g[i] = (float) r.nextGaussian();
        }
        return g;
    }

    static List<EvidenceRecord> frames(int n, java.util.function.IntFunction<float[]> crop) {
        List<EvidenceRecord> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(new EvidenceRecord(1, i, 1_000_000_000L * i / 15, i * 67L, 1, true, null, 0.95f, LM,
                    new float[] {10, 10, 44, 54}, crop.apply(i), 0f));
        }
        return out;
    }

    @Test
    void noFramesOrTooFewFramesIsInsufficientNeverVarying() {
        assertEquals(Verdict.INSUFFICIENT_FRAMES, DET.assess(Collections.emptyList()).verdict);
        assertEquals(Verdict.INSUFFICIENT_FRAMES, DET.assess(frames(1, i -> texture(1))).verdict);
        assertEquals(Verdict.INSUFFICIENT_FRAMES, DET.assess(frames(P.staticMinPairs, i -> texture(i))).verdict, "10 frames = 9 pairs < 10");
        assertNotEquals(Verdict.INSUFFICIENT_FRAMES, DET.assess(frames(P.staticMinPairs + 1, i -> texture(i))).verdict);
    }

    @Test
    void recordsWithoutLandmarksOrCropsAreSkippedNotCounted() {
        List<EvidenceRecord> mixed = new ArrayList<>();
        for (EvidenceRecord r : frames(40, i -> texture(i))) {
            mixed.add(new EvidenceRecord(r.epoch, r.seq, r.monoNanos, r.wallMillis, 1, true, null, 0.95f,
                    r.seq % 2 == 0 ? null : LM, new float[] {10, 10, 44, 54}, r.seq % 3 == 0 ? null : r.alignedGrey, 0f));
        }
        StaticReplayDetector.Assessment a = DET.assess(mixed);
        assertTrue(a.pairs < 39, "unusable records produce no pairs: " + a);
    }

    @Test
    void aPerfectlyIdenticalStreamIsStaticNotMoving() {
        float[] same = texture(7);
        StaticReplayDetector.Assessment a = DET.assess(frames(60, i -> same.clone()));
        assertEquals(Verdict.STATIC_SUSPECT, a.verdict, a.toString());
        assertEquals(0, a.varyingPairs);
        assertTrue(a.maxPhoto < 0.01, "identical crops leave no residual: " + a);
    }

    @Test
    void unrelatedFramesEveryTimeCountAsMotion() {
        StaticReplayDetector.Assessment a = DET.assess(frames(60, i -> texture(1000 + i)));
        assertEquals(Verdict.VARYING, a.verdict, a.toString());
    }

    @Test
    void aSingleDifferentPairInALongStaticRunIsEnoughAndExactlyThatMany() {
        float[] still = texture(3), other = texture(4);
        // 50 identical frames, one different frame in the middle -> two pairs touch it, both vary
        StaticReplayDetector.Assessment a = DET.assess(frames(50, i -> i == 25 ? other.clone() : still.clone()));
        assertEquals(Verdict.VARYING, a.verdict, a.toString());
        assertEquals(2, a.varyingPairs, a.toString());
        // the last frame different: only one pair
        StaticReplayDetector.Assessment b = DET.assess(frames(50, i -> i == 49 ? other.clone() : still.clone()));
        assertEquals(1, b.varyingPairs, b.toString());
    }

    @Test
    void nanOrInfiniteCropsAreNeverCountedAsMotion() {
        float[] still = texture(5);
        float[] nan = still.clone();
        nan[100] = Float.NaN;
        float[] inf = still.clone();
        inf[200] = Float.POSITIVE_INFINITY;
        for (float[] bad : new float[][] {nan, inf}) {
            StaticReplayDetector.Assessment a = DET.assess(frames(40, i -> i % 2 == 0 ? still.clone() : bad.clone()));
            assertNotEquals(Verdict.VARYING, a.verdict, "corrupt pixels must not look like motion: " + a);
        }
    }

    @Test
    void photoResidualOfIdenticalAndOfTranslatedTexturesStaysBelowTheMotionLine() {
        float[] base = texture(11);
        assertEquals(0.0, StaticReplayDetector.photoResidual(base, base.clone()), 1e-6);
        // brightness/contrast change and noise are removed by standardisation: still "static"
        float[] scaled = new float[base.length];
        for (int i = 0; i < base.length; i++) {
            scaled[i] = base[i] * 3f + 40f;
        }
        assertTrue(StaticReplayDetector.photoResidual(base, scaled) < P.staticPhotoThreshold);
    }

    /**
     * RESIDUAL RISK (documented, behaviour unchanged): a crop with no texture at all (constant) or of unexpected size
     * cannot be standardised, so its residual is +Infinity, which is above the threshold and therefore counts as
     * "varying". An eligible live frame cannot reach this (quality gates need a sharp face), but a future caller that
     * feeds such crops would see them treated as motion. Pinned so any change to this semantic is a visible decision.
     */
    @Test
    void textureFreeOrMisSizedCropsCountAsVarying_residualRisk() {
        float[] flat = new float[64 * 64];
        Arrays.fill(flat, 0.5f);
        assertEquals(Double.POSITIVE_INFINITY, StaticReplayDetector.photoResidual(flat, flat.clone()), 0.0);
        assertEquals(Double.POSITIVE_INFINITY, StaticReplayDetector.photoResidual(texture(1), new float[63 * 63]), 0.0);
        assertEquals(Double.POSITIVE_INFINITY, StaticReplayDetector.photoResidual(new float[50], new float[50]), 0.0);   // not square
        assertEquals(Verdict.VARYING, DET.assess(frames(40, i -> flat.clone())).verdict);
    }
}
