package io.mosip.liveness.binding;

import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.binding.BindingResult.Reason;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static io.mosip.liveness.binding.CaptureBinderTest.GOOD;
import static io.mosip.liveness.binding.CaptureBinderTest.OTHER;
import static io.mosip.liveness.binding.CaptureBinderTest.SERIAL;
import static io.mosip.liveness.binding.CaptureBinderTest.SUBJECT;
import static io.mosip.liveness.binding.CaptureBinderTest.bind;
import static io.mosip.liveness.binding.CaptureBinderTest.binder;
import static io.mosip.liveness.binding.CaptureBinderTest.ctx;
import static io.mosip.liveness.binding.CaptureBinderTest.expect;
import static io.mosip.liveness.binding.CaptureBinderTest.response;
import static io.mosip.liveness.binding.CaptureBinderTest.stub;
import static io.mosip.liveness.binding.CaptureBinderTest.unit;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Exact-boundary and degenerate-value tests for the capture decision (PAD gate, subject similarity, evidence count).
 * Off-by-one at a threshold is the classic way a security gate leaks, so every edge is pinned from both sides. [CODE]
 * Thresholds are the existing defaults (accept 0.80, attack 0.20, cosine 0.50, 3 stream embeddings); none is changed here.
 */
class ThresholdBoundaryTest {
    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
    }

    private static void padExpect(float pad, Outcome o, Reason r) throws Exception {
        expect(bind(c -> { }, stub(1, pad, SUBJECT)), o, r);
    }

    @Test
    void capturePadGateIsExactOnBothSidesOfEveryThreshold() throws Exception {
        padExpect(0.0f, Outcome.ATTACK, Reason.PAD_ATTACK);
        padExpect(-0.0f, Outcome.ATTACK, Reason.PAD_ATTACK);
        padExpect(Math.nextDown(0.20f), Outcome.ATTACK, Reason.PAD_ATTACK);         // just below the attack line
        padExpect(0.20f, Outcome.UNCERTAIN, Reason.PAD_UNCERTAIN);                  // exactly 0.20 is NOT an attack
        padExpect(Math.nextUp(0.20f), Outcome.UNCERTAIN, Reason.PAD_UNCERTAIN);
        padExpect(Math.nextDown(0.80f), Outcome.UNCERTAIN, Reason.PAD_UNCERTAIN);   // just below the accept gate: never bound
        padExpect(0.80f, Outcome.BOUND, Reason.OK);                                 // exactly 0.80 binds
        padExpect(Math.nextUp(0.80f), Outcome.BOUND, Reason.OK);
        padExpect(1.0f, Outcome.BOUND, Reason.OK);
    }

    @Test
    void aPadScoreOutsideTheProbabilityRangeNeverBinds() throws Exception {
        for (float bad : new float[] {Math.nextUp(1.0f), 1.5f, 7f, 1e30f, Float.MAX_VALUE, Float.POSITIVE_INFINITY,
                Float.NEGATIVE_INFINITY, Float.NaN}) {
            assertNotEquals(Outcome.BOUND, bind(c -> { }, stub(1, bad, SUBJECT)).outcome, "pad " + bad + " must not bind");
        }
    }

    private static float[] atCosine(float c) {
        // SUBJECT is the first axis, so cos(SUBJECT, v) = v[0]; the second component only matters for the norm
        return unit(c, (float) Math.sqrt(Math.max(0.0, 1.0 - (double) c * c)));
    }

    @Test
    void subjectSimilarityIsExactlyAtTheLine() throws Exception {
        expect(bind(c -> { }, stub(1, 0.95f, atCosine(0.5f))), Outcome.BOUND, Reason.OK);                     // exactly 0.50
        expect(bind(c -> { }, stub(1, 0.95f, atCosine(Math.nextUp(0.5f)))), Outcome.BOUND, Reason.OK);
        expect(bind(c -> { }, stub(1, 0.95f, atCosine(Math.nextDown(0.5f)))), Outcome.REJECTED, Reason.SUBJECT_MISMATCH);
        expect(bind(c -> { }, stub(1, 0.95f, atCosine(0.0f))), Outcome.REJECTED, Reason.SUBJECT_MISMATCH);   // orthogonal
        expect(bind(c -> { }, stub(1, 0.95f, atCosine(-1.0f))), Outcome.REJECTED, Reason.SUBJECT_MISMATCH);  // opposite
    }

    @Test
    void degenerateEmbeddingsNeverBind() throws Exception {
        float[] zero = new float[128];
        float[] inf = unit(Float.POSITIVE_INFINITY, 0f);
        float[] negInf = unit(Float.NEGATIVE_INFINITY, 0f);
        float[] nan = unit(Float.NaN, 0f);
        float[] huge = unit(1e30f, 0f);                                    // not unit length: would "match" by sheer norm
        float[] tooShort = new float[] {1f};                               // would match on the one component it has
        float[] tooLong = new float[129];
        tooLong[0] = 1f;
        for (float[] e : new float[][] {zero, inf, negInf, nan, huge, tooShort, tooLong, new float[0]}) {
            BindingResult r = bind(c -> { }, stub(1, 0.95f, e));
            assertNotEquals(Outcome.BOUND, r.outcome, "embedding of length " + e.length + " [0]=" + (e.length > 0 ? e[0] : 0f) + " -> " + r);
        }
    }

    @Test
    void streamEvidenceCountIsExactlyThree() throws Exception {
        for (int n : new int[] {0, 1, 2}) {
            BindingResult r = binder(GOOD).bind(response(c -> { }), ctx(n), Instant.now());
            expect(r, Outcome.UNCERTAIN, Reason.INSUFFICIENT_STREAM_EVIDENCE);
        }
        for (int n : new int[] {3, 4, 50}) {
            expect(binder(GOOD).bind(response(c -> { }), ctx(n), Instant.now()), Outcome.BOUND, Reason.OK);
        }
    }

    private static CaptureBinder.SessionContext mix(int same, int other) {
        List<float[]> e = new ArrayList<>();
        for (int i = 0; i < same; i++) {
            e.add(SUBJECT);
        }
        for (int i = 0; i < other; i++) {
            e.add(OTHER);
        }
        return new CaptureBinder.SessionContext("txn-1", SERIAL, "Phase0", "MOCK-FACE-1", Instant.now().minusSeconds(10), e);
    }

    @Test
    void theSubjectDecisionIsTheMedianSoAMinorityOfOtherFacesCannotFlipItEitherWay() throws Exception {
        // 3 matching + 2 other: the median is a match, so two stray frames do not reject the genuine person
        expect(binder(GOOD).bind(response(c -> { }), mix(3, 2), Instant.now()), Outcome.BOUND, Reason.OK);
        // 2 matching + 3 other: the median is a mismatch, so a stream that is mostly someone else cannot bind to this capture
        expect(binder(GOOD).bind(response(c -> { }), mix(2, 3), Instant.now()), Outcome.REJECTED, Reason.SUBJECT_MISMATCH);
        // all frames someone else
        expect(binder(GOOD).bind(response(c -> { }), mix(0, 5), Instant.now()), Outcome.REJECTED, Reason.SUBJECT_MISMATCH);
        // an even count uses the upper-middle element (cos[n/2]): 2 matching + 2 other -> the second sorted value is a match
        expect(binder(GOOD).bind(response(c -> { }), mix(2, 2), Instant.now()), Outcome.BOUND, Reason.OK);
        // ...but 1 matching + 3 other is not
        expect(binder(GOOD).bind(response(c -> { }), mix(1, 3), Instant.now()), Outcome.REJECTED, Reason.SUBJECT_MISMATCH);
    }

    @Test
    void padAttackOutranksEverythingThatFollowsItIncludingAGoodMatch() throws Exception {
        expect(bind(c -> { }, stub(1, 0.0f, SUBJECT)), Outcome.ATTACK, Reason.PAD_ATTACK);
        expect(binder(stub(1, 0.0f, SUBJECT)).bind(response(c -> { }), ctx(0), Instant.now()), Outcome.ATTACK, Reason.PAD_ATTACK);
    }
}
