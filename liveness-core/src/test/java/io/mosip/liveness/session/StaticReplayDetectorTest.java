package io.mosip.liveness.session;

import io.mosip.liveness.vision.Phase0Models;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Static-image replay detection on the [SIM] temporal fixtures (research/fixtures/temporal), through the real pipeline.
 *
 * <p>static_replay sequences are ONE still photo re-encoded per frame (JPEG q70-95) with small random shift/rotation/
 * scale, brightness/contrast change and sensor noise — not byte-identical frames. animate sequences add synthetic
 * non-rigid motion (blink, mouth). Sources T1/lfwA/lfwB/lfwC were used to choose the threshold; hoD/hoE/hoF are held out
 * and were not looked at when choosing it. [SIM] evidence only: synthetic motion is not real human motion, and
 * a real still user is expected to be flagged (documented limit, fails closed to retry).
 */
class StaticReplayDetectorTest {
    static Phase0Models models;
    static final SessionPolicy P = new SessionPolicy();
    static final StaticReplayDetector DET = new StaticReplayDetector(P.staticPhotoThreshold, P.staticMinPairs, P.staticMinVaryingPairs);

    @BeforeAll
    static void load() throws Exception {
        models = Phase0Models.load(TemporalFixtures.root(), 1, 320, false);
    }

    @AfterAll
    static void close() throws Exception {
        models.close();
    }

    static StaticReplayDetector.Assessment assess(String kind, String src) throws Exception {
        List<EvidenceRecord> el = new ArrayList<>();
        for (EvidenceRecord r : TemporalFixtures.records(models, kind, src)) {
            if (r.eligible) {
                el.add(r);
            }
        }
        assertTrue(el.size() >= P.staticMinPairs + 1, kind + "/" + src + " eligible=" + el.size());
        StaticReplayDetector.Assessment a = DET.assess(el);
        System.out.println("STATIC-REPLAY " + kind + "/" + src + " " + a);
        return a;
    }

    @ParameterizedTest
    @ValueSource(strings = {"T1", "lfwA", "lfwB", "lfwC", "hoD", "hoE", "hoF"})
    void reencodedTransformedStillPhotoIsStaticSuspect(String src) throws Exception {
        assertEquals(StaticReplayDetector.Verdict.STATIC_SUSPECT, assess("static_replay", src).verdict);
    }

    @ParameterizedTest
    @ValueSource(strings = {"T1", "lfwA", "lfwB", "lfwC", "hoD", "hoE", "hoF"})
    void syntheticNonRigidMotionIsVarying(String src) throws Exception {
        assertEquals(StaticReplayDetector.Verdict.VARYING, assess("animate", src).verdict);
    }

    @ParameterizedTest
    @ValueSource(strings = {"T1", "hoD"})
    void tooFewFramesIsInsufficientNotVarying(String src) throws Exception {
        List<EvidenceRecord> rs = TemporalFixtures.records(models, "animate", src);
        assertEquals(StaticReplayDetector.Verdict.INSUFFICIENT_FRAMES, DET.assess(rs.subList(0, 5)).verdict);
    }
}
