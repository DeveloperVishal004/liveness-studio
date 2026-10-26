package io.mosip.liveness.session;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The per-pair residual cache (cost fix: ~215 ms -> ~3 ms per frame under the session lock, [M1]) must not change any
 * assessment: cached results must equal a full recomputation for contiguous windows, windows with records removed
 * (e.g. B1 keeps only covered frames), and lists spanning an attempt boundary. [CODE]
 */
class StaticResidualCacheTest {
    static final float[][] LM = {{20, 24}, {44, 24}, {32, 36}, {24, 48}, {40, 48}};

    static EvidenceRecord rec(long epoch, long seq, Random r, boolean still, float[] base) {
        float[] g = new float[64 * 64];
        for (int i = 0; i < g.length; i++) {
            g[i] = still ? base[i] + (float) (r.nextGaussian() * 0.01) : (float) r.nextGaussian();
        }
        float[][] lm = new float[5][2];
        for (int i = 0; i < 5; i++) {
            lm[i][0] = LM[i][0] + (float) r.nextGaussian() * 0.3f;
            lm[i][1] = LM[i][1] + (float) r.nextGaussian() * 0.3f;
        }
        return new EvidenceRecord(epoch, seq, seq * 66_666_667L, 0, 1, true, null, 0.9f, lm, null, g, 0f);
    }

    /** Same records without cached values (fresh objects sharing the pixel data). */
    static List<EvidenceRecord> uncached(List<EvidenceRecord> in) {
        List<EvidenceRecord> out = new ArrayList<>();
        for (EvidenceRecord r : in) {
            out.add(new EvidenceRecord(r.epoch, r.seq, r.monoNanos, r.wallMillis, r.faceCount, r.eligible, r.ineligibleReason,
                    r.pad, r.landmarks, r.faceBox, r.alignedGrey, r.yawProxy));
        }
        return out;
    }

    static void assertSame(StaticReplayDetector d, List<EvidenceRecord> list) {
        StaticReplayDetector.Assessment a = d.assess(list), b = d.assess(uncached(list));
        assertEquals(b.verdict, a.verdict);
        assertEquals(b.pairs, a.pairs);
        assertEquals(b.varyingPairs, a.varyingPairs);
        assertEquals(b.maxPhoto, a.maxPhoto, 0.0);
        assertEquals(b.maxGeom, a.maxGeom, 0.0);
    }

    @Test
    void cachedAssessmentEqualsFullRecomputation() {
        StaticReplayDetector d = new StaticReplayDetector(0.40, 10, 1);
        Random r = new Random(3);
        float[] base = new float[64 * 64];
        for (int i = 0; i < base.length; i++) {
            base[i] = (float) r.nextGaussian();
        }
        List<EvidenceRecord> all = new ArrayList<>();
        EvidenceRecord prev = null;
        for (int i = 0; i < 60; i++) {
            EvidenceRecord e = rec(i < 40 ? 1 : 2, i, r, i % 7 != 0, base);   // mostly still, occasional change; epoch 1 -> 2
            if (prev != null && prev.epoch == e.epoch) {
                StaticReplayDetector.cacheResiduals(prev, e);
            }
            all.add(e);
            prev = e;
        }
        assertSame(d, all.subList(0, 40));                 // contiguous, one epoch
        assertSame(d, all.subList(5, 35));                 // contiguous window not starting at the first record
        assertSame(d, all);                                // spans the attempt boundary
        List<EvidenceRecord> gaps = new ArrayList<>(all.subList(0, 40));
        gaps.remove(20);
        gaps.remove(10);
        gaps.remove(3);
        assertSame(d, gaps);                               // non-contiguous (B1 coverage filter): must recompute
    }

    @Test
    void cacheRefusesMismatchedPairs() {
        Random r = new Random(4);
        float[] base = new float[64 * 64];
        EvidenceRecord a = rec(1, 1, r, false, base), b = rec(2, 2, r, false, base);
        StaticReplayDetector.cacheResiduals(a, b);
        assertEquals(Long.MIN_VALUE, b.residualPrevSeq, "no cache across epochs");
        StaticReplayDetector.cacheResiduals(null, b);
        assertEquals(Long.MIN_VALUE, b.residualPrevSeq);
    }
}
