package io.mosip.liveness.frame;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FrameHandoffTest {

    @Test
    void mailboxKeepsOnlyNewestAndCountsOverwrites() throws Exception {
        LatestFrameMailbox<Integer> m = new LatestFrameMailbox<>();
        assertFalse(m.offer(1));
        assertTrue(m.offer(2));
        assertTrue(m.offer(3));
        assertEquals(3, m.take(10, TimeUnit.MILLISECONDS));
        assertNull(m.take(10, TimeUnit.MILLISECONDS));
        assertEquals(2, m.overwrittenCount());
        assertEquals(3, m.offeredCount());
    }

    @Test
    void closedMailboxReleasesWaitersAndRejectsOffers() throws Exception {
        LatestFrameMailbox<Integer> m = new LatestFrameMailbox<>();
        Thread t = new Thread(m::close);
        t.start();
        assertNull(m.take(5, TimeUnit.SECONDS));
        assertFalse(m.offer(1));
    }

    @Test
    void gateAcceptsOnlyCurrentSessionEpochAndIncreasingSeq() {
        EvidenceGate g = EvidenceGate.open();
        byte[] sid = g.sessionId();
        assertEquals(EvidenceGate.Verdict.ACCEPTED, g.check(sid, 0, 1, 100));
        assertEquals(EvidenceGate.Verdict.OUT_OF_ORDER, g.check(sid, 0, 1, 101));
        assertEquals(EvidenceGate.Verdict.ACCEPTED, g.check(sid, 0, 2, 102));
        assertEquals(EvidenceGate.Verdict.WRONG_SESSION, g.check(EvidenceGate.open().sessionId(), 0, 3, 103));
    }

    @Test
    void newEpochInvalidatesOldEvidenceAndEnforcesFreshnessFloor() {
        EvidenceGate g = EvidenceGate.open();
        byte[] sid = g.sessionId();
        assertEquals(EvidenceGate.Verdict.ACCEPTED, g.check(sid, 0, 10, 1_000));
        g.advanceEpoch(5_000);  // e.g. challenge issued at t=4_700 with a 300 ns guard
        assertEquals(EvidenceGate.Verdict.STALE_EPOCH, g.check(sid, 0, 11, 6_000));
        assertEquals(EvidenceGate.Verdict.BEFORE_FRESHNESS_FLOOR, g.check(sid, 1, 11, 4_999));
        assertEquals(EvidenceGate.Verdict.ACCEPTED, g.check(sid, 1, 12, 5_000));
        g.close();
        assertEquals(EvidenceGate.Verdict.SESSION_CLOSED, g.check(sid, 1, 13, 7_000));
    }

    @Test
    void freshnessComparisonIsOverflowSafe() {
        EvidenceGate g = EvidenceGate.open();
        long floor = Long.MAX_VALUE - 10;
        g.advanceEpoch(floor);
        // nanoTime may wrap; a frame 20 ns after the floor is fresh even though it is numerically negative
        assertEquals(EvidenceGate.Verdict.ACCEPTED, g.check(g.sessionId(), 1, 1, floor + 20));
    }

    @Test
    void sessionIdsAreUnpredictableAndDistinct() {
        assertFalse(java.util.Arrays.equals(EvidenceGate.open().sessionId(), EvidenceGate.open().sessionId()));
        assertEquals(16, EvidenceGate.open().sessionId().length);
    }
}
