package io.mosip.liveness.session;

import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exact-boundary tests for the session's stream decision: the 3-frame attack count, the 0.20 attack line, the 0.80
 * median gate, and invalid evidence. Fake clock, synthetic [SIM] evidence; defaults unchanged. [CODE]
 */
class SessionBoundaryTest {
    final SessionHarness.StubVerifier verifier = new SessionHarness.StubVerifier();

    SessionHarness fresh() {
        SessionHarness h = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), verifier, null);
        h.session.start();
        return h;
    }

    @Test
    void twoAttackFramesAreToleratedAndTheThirdRejectsTheAttemptEvenWhenSeparatedByGoodFrames() {
        SessionHarness h = fresh();
        h.pad = 0.10f;
        h.frames(2, Kind.LIVE);
        assertNotEquals(State.REJECTED_ATTACK, h.session.state(), "two low frames are not yet an attack");
        h.pad = 0.95f;
        h.frames(6, Kind.LIVE);                                            // good frames do not erase the count
        assertNotEquals(State.REJECTED_ATTACK, h.session.state());
        h.pad = 0.10f;
        h.frames(1, Kind.LIVE);
        assertEquals(State.REJECTED_ATTACK, h.session.state());
        assertEquals(Reason.STREAM_PAD_ATTACK, h.session.outcome().reason);
        assertEquals(1, h.session.outcome().attackEvents);
        assertEquals(null, h.session.outcome().verifiedCaptureSha256);
    }

    @Test
    void aFrameExactlyAtTheAttackLineDoesNotCountButOneUlpBelowDoes() {
        SessionHarness h = fresh();
        h.pad = 0.20f;
        h.frames(60, Kind.LIVE);
        assertEquals(State.CAPTURING, h.session.state(), "0.20 is uncertain, not an attack, however many frames");
        // it never becomes ready either (median 0.20 < 0.80) and ends in a retry, never an acceptance
        h.clock.advance(11_000);
        SessionOutcome o = h.session.tick();
        assertEquals(State.RETRY_PENDING, o.state);
        assertEquals(Reason.PASSIVE_UNCERTAIN_NO_CHALLENGE, o.reason);

        SessionHarness g = fresh();
        g.pad = Math.nextDown(0.20f);
        g.frames(3, Kind.LIVE);
        assertEquals(State.REJECTED_ATTACK, g.session.state());
    }

    @Test
    void theMedianGateIsExactlyAtPointEight() {
        SessionHarness at = fresh();
        at.pad = 0.80f;
        assertEquals(State.READY_FOR_CAPTURE, at.untilReady(), "median exactly 0.80 is accepted");

        SessionHarness below = fresh();
        below.pad = Math.nextDown(0.80f);
        assertEquals(State.CAPTURING, below.untilReady(), "median one ulp below 0.80 is never ready");
    }

    @Test
    void aMinorityOfLowFramesDoesNotMoveTheMedianPastTheGateButTheirCountStillCounts() {
        // 7 good frames and 2 low frames: median stays high, only 2 attack frames -> still allowed to become ready
        SessionHarness h = fresh();
        h.pad = 0.10f;
        h.frames(2, Kind.LIVE);
        h.pad = 0.95f;
        State s = h.untilReady();
        assertEquals(State.READY_FOR_CAPTURE, s);
        assertEquals(0, h.session.outcome().attackEvents);
    }

    @Test
    void nonFiniteOrOutOfRangePadIsInvalidEvidenceAndNeverMakesTheSessionReady() {
        for (float bad : new float[] {Float.NaN, Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY, -0.0001f, Math.nextUp(1.0f), 5f}) {
            SessionHarness h = fresh();
            for (int i = 0; i < 40; i++) {
                h.clock.advance(67);
                FrameTag t = h.session.tagArrival();
                h.session.onEvidence(t, 1, true, null, bad, SessionHarness.LM, new float[] {10, 10, 44, 54},
                        SessionHarness.texture(new java.util.Random(i)), 0f);
            }
            SessionOutcome o = h.session.outcome();
            assertEquals(State.CAPTURING, o.state, "pad " + bad);
            assertEquals(40, o.invalidEvidence, "every bad score is counted and discarded, pad " + bad);
            assertEquals(0, o.attackEvents, "garbage is not an attack verdict either, pad " + bad);
        }
    }

    @Test
    void anEligibleFrameWithoutAnAlignedCropIsInvalidEvidence() {
        SessionHarness h = fresh();
        for (int i = 0; i < 20; i++) {
            h.clock.advance(67);
            h.session.onEvidence(h.session.tagArrival(), 1, true, null, 0.99f, SessionHarness.LM, new float[] {10, 10, 44, 54}, null, 0f);
        }
        assertEquals(20, h.session.outcome().invalidEvidence);
        assertEquals(State.CAPTURING, h.session.state());
    }

    @Test
    void ineligibleFramesNeverContributeEvenWithAPerfectPadValueAttached() {
        SessionHarness h = fresh();
        for (int i = 0; i < 100; i++) {
            h.clock.advance(67);
            // not eligible (too small) but carrying a "perfect" score and a would-be-attack score alternately
            h.session.onEvidence(h.session.tagArrival(), 1, false, "FACE_TOO_SMALL", (i % 2 == 0) ? 1.0f : 0.0f,
                    SessionHarness.LM, new float[] {10, 10, 44, 54}, SessionHarness.texture(new java.util.Random(i)), 0f);
        }
        SessionOutcome o = h.session.tick();
        assertTrue(o.state == State.CAPTURING || o.state == State.RETRY_PENDING, o.toString());
        assertNotEquals(State.READY_FOR_CAPTURE, o.state);
        assertNotEquals(State.REJECTED_ATTACK, o.state, "ineligible frames cannot trigger the attack count");
    }

    @Test
    void aFrameFromAnyOtherSessionOrOutOfOrderIsStaleAndChangesNothing() {
        SessionHarness h = fresh();
        h.frames(3, Kind.LIVE);
        FrameTag old = h.tags.get(0);
        long staleBefore = h.session.outcome().droppedStaleFrames;
        h.session.onEvidence(old, 1, true, null, 0.99f, SessionHarness.LM, new float[] {10, 10, 44, 54},
                SessionHarness.texture(new java.util.Random(1)), 0f);                    // replayed older tag
        assertEquals(staleBefore + 1, h.session.outcome().droppedStaleFrames);
        h.session.onEvidence(null, 1, true, null, 0.99f, SessionHarness.LM, new float[] {10, 10, 44, 54},
                SessionHarness.texture(new java.util.Random(2)), 0f);                    // no tag at all
        assertEquals(staleBefore + 2, h.session.outcome().droppedStaleFrames);
        assertEquals(State.CAPTURING, h.session.state());
    }
}
