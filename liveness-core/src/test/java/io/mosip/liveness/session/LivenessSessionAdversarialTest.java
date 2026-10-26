package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Adversarial verification of the review fixes (findings 1, 2, 4) across event paths, plus the "a failed attempt cannot
 * later verify" checks. [CODE] evidence with synthetic per-frame evidence; tests named *_residualRisk CHARACTERIZE a
 * known gap (they assert the current, undesired behaviour so a change is noticed) and are not desired outcomes.
 */
class LivenessSessionAdversarialTest {
    static final byte[] RESP = "{}".getBytes(StandardCharsets.UTF_8);
    SessionHarness.StubVerifier verifier = new SessionHarness.StubVerifier();

    SessionHarness harness(SessionPolicy p) {
        return new SessionHarness(p, new AttemptLedger.InMemory(), verifier, null);
    }

    static BindingResult bound(float[] emb) {
        return BindingResult.of(Outcome.BOUND, BindingResult.Reason.OK, SessionHarness.HASH, emb);
    }

    static void expect(SessionOutcome o, State s, Reason r) {
        assertEquals(s + "/" + r, o.state + "/" + o.reason, o.toString());
    }

    // ================================================================ finding 2 / clock: wall transient at the request
    /**
     * Wall clock stepped back 10 min exactly while beginCapture runs, then restored before the response. The drift check
     * at the response sees no drift, so the window handed to the binder must still be derived from the attempt baseline
     * (monotonic), not from the transient wall reading.
     */
    @Test
    void transientWallStepAtBeginCaptureDoesNotShiftTheBindingWindow() {
        SessionHarness h = harness(new SessionPolicy());
        h.session.start();
        h.untilReady();
        long trueWallAtReq = h.clock.wall;
        h.clock.wall -= 600_000;
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.clock.wall += 600_000;
        h.frames(10, Kind.LIVE);
        verifier.next = bound(SessionHarness.SUBJECT);
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, RESP);
        var ctx = verifier.seen.get(0);
        assertEquals(trueWallAtReq - 300, ctx.windowFrom.toEpochMilli(), "window shifted by a transient wall reading");
        expect(o, State.VERIFIED, Reason.OK);
    }

    // ================================================================ finding 1: subject ledger across paths
    /** Embeddings for subject-A frames still pending when the response arrives are not awaited (characterization). */
    @Test
    void pendingEmbeddingsAtDecisionTimeAreNotAwaited_residualRisk() {
        SessionHarness h = harness(new SessionPolicy());
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(8, Kind.LIVE);                       // subject B frames with embeddings
        h.embed = false;
        h.frames(2, Kind.LIVE);                       // two more frames whose embeddings are still in flight
        int n = h.tags.size();
        verifier.next = bound(SessionHarness.SUBJECT);
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, RESP);
        // the in-flight embeddings turn out to be subject A, after the decision: dropped (gates closed)
        h.session.onEmbedding(h.tags.get(n - 2), SessionHarness.OTHER);
        h.session.onEmbedding(h.tags.get(n - 1), SessionHarness.OTHER);
        expect(o, State.VERIFIED, Reason.OK);
        assertEquals(State.VERIFIED, h.session.state());
        assertTrue(h.session.outcome().droppedStaleEmbeddings >= 2);
    }

    /** Subject consistency covers frontal frames only: subject A shown only off-frontal is not compared (characterization). */
    @Test
    void subjectShownOnlyOffFrontalIsNotCompared_residualRisk() {
        SessionHarness h = harness(new SessionPolicy());
        h.embedding = SessionHarness.OTHER;           // subject A ...
        h.yaw = 0.6f;                                  // ... always turned away (|yaw proxy| > frontalMaxAbsYaw)
        h.session.start();
        assertEquals(State.READY_FOR_CAPTURE, h.untilReady());
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.embedding = SessionHarness.SUBJECT;          // subject B frontal at capture
        h.yaw = 0f;
        h.frames(10, Kind.LIVE);
        verifier.next = bound(SessionHarness.SUBJECT);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.VERIFIED, Reason.OK);
    }

    /** Embeddings for frames whose record was already evicted still enter the subject ledger (pose unknown). */
    @Test
    void evictedButInOrderEmbeddingIsCheckedAgainstTheCapture() {
        SessionPolicy p = new SessionPolicy();
        p.maxRecords = 80;
        p.readyTimeoutMs = 60_000;
        SessionHarness h = harness(p);
        h.session.start();
        h.embed = false;
        h.untilReady();
        int k = h.tags.size();
        h.frames(100, Kind.LIVE);                      // evicts frame k's record
        h.session.onEmbedding(h.tags.get(k), SessionHarness.OTHER);   // first embedding delivered: in order, record gone
        h.embed = true;
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        verifier.next = bound(SessionHarness.SUBJECT);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.REJECTED_ATTACK, Reason.SUBJECT_CHANGED);
    }

    // ================================================================ item 4: failed / overflowed attempts never verify
    @Test
    void overflowedAttemptCannotVerifyViaLateResponseOrStaleAsyncResults() {
        SessionPolicy p = new SessionPolicy();
        p.maxAttemptEmbeddings = 5;
        SessionHarness h = harness(p);
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        verifier.next = bound(SessionHarness.SUBJECT);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.ATTEMPT_EVIDENCE_OVERFLOW);
        // same response again, and stale async results of the overflowed attempt
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, RESP);
        expect(o, State.RETRY_PENDING, Reason.ATTEMPT_EVIDENCE_OVERFLOW);
        FrameTag old = h.tags.get(h.tags.size() - 1);
        h.session.retry();
        h.deliver(old, Kind.LIVE);
        h.session.onEmbedding(old, SessionHarness.SUBJECT);
        h.session.onCaptureResponse(req.transactionId, RESP);
        assertEquals(State.CAPTURING, h.session.state());
        assertEquals(1, verifier.seen.size(), "nothing from the overflowed attempt was bound again");
        assertTrue(h.session.outcome().ignoredLateResponses >= 2);
    }

    @Test
    void retryAfterOverflowStartsFromEmptyStateAndNeedsFreshEvidence() {
        SessionPolicy p = new SessionPolicy();
        p.maxAttemptEmbeddings = 40;
        SessionHarness h = harness(p);
        h.session.start();
        h.untilReady();
        h.frames(30, Kind.LIVE);                       // > 40 embeddings in total -> overflow flag set
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        verifier.next = bound(SessionHarness.SUBJECT);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.ATTEMPT_EVIDENCE_OVERFLOW);
        h.session.retry();
        assertThrowsIllegalState(h);                   // readiness is not carried over
        h.untilReady();
        req = h.session.beginCapture();
        h.frames(8, Kind.LIVE);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.VERIFIED, Reason.OK);
        assertEquals(2, h.session.outcome().attempt, "verification came from a new, counted attempt");
    }

    private static void assertThrowsIllegalState(SessionHarness h) {
        try {
            h.session.beginCapture();
            throw new AssertionError("beginCapture allowed right after retry");
        } catch (IllegalStateException expected) {
            // ok
        }
    }

    @Test
    void subjectChangedAttemptCannotVerifyAndCountsTowardTheAttackLimit() {
        SessionHarness h = harness(new SessionPolicy());
        h.embedding = SessionHarness.OTHER;
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.embedding = SessionHarness.SUBJECT;
        h.frames(10, Kind.LIVE);
        verifier.next = bound(SessionHarness.SUBJECT);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.REJECTED_ATTACK, Reason.SUBJECT_CHANGED);
        assertEquals(State.REJECTED_ATTACK, h.session.onCaptureResponse(req.transactionId, RESP).state);
        h.session.retry();                             // attack 1 tolerated (maxAttackEvents = 1)
        h.embedding = SessionHarness.OTHER;
        h.untilReady();
        req = h.session.beginCapture();
        h.embedding = SessionHarness.SUBJECT;
        h.frames(10, Kind.LIVE);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.REJECTED_ATTACK, Reason.SUBJECT_CHANGED);
        expect(h.session.retry(), State.FAILED_MAX_RETRIES, Reason.ATTACK_LIMIT);
    }

    @Test
    void timedOutAttemptCannotVerifyWhenTheResponseArrivesLateWithoutTick() {
        SessionHarness h = harness(new SessionPolicy());
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        h.clock.advance(15_100);                       // no tick, no events during the wait
        verifier.next = bound(SessionHarness.SUBJECT);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.CAPTURE_TIMEOUT);
        assertTrue(verifier.seen.isEmpty());
    }

    @Test
    void readyTimeoutIsEnforcedByBeginCaptureWithoutTick() {
        SessionHarness h = harness(new SessionPolicy());
        h.session.start();
        h.untilReady();
        h.clock.advance(5_100);
        assertThrowsIllegalState(h);
        expect(h.session.outcome(), State.RETRY_PENDING, Reason.CAPTURE_NOT_STARTED);
    }

    @Test
    void ttlIsEnforcedByEvidenceEventsWithoutTick() {
        SessionHarness h = harness(new SessionPolicy());
        h.session.start();
        h.clock.advance(121_000);
        h.frames(1, Kind.LIVE);
        expect(h.session.outcome(), State.EXPIRED, Reason.SESSION_EXPIRED);
    }

    // ================================================================ finding 2: timestamp paths
    @Test
    void rejectedTimestampsNeverAffectReadinessOrTheWindow() {
        SessionHarness h = harness(new SessionPolicy());
        h.session.start();
        for (int i = 0; i < 60; i++) {                 // a transport that forward-dates every frame by 50 ms
            h.clock.advance(67);
            assertNull(h.session.tagArrival(i, h.clock.mono + 50_000_000L, h.clock.wall + 50));
        }
        assertEquals(State.CAPTURING, h.session.state());
        assertEquals(60, h.session.outcome().rejectedArrivalTimestamps);
    }

    @Test
    void preIssuedTrustedTagsAreCallerResponsibility_residualRisk() {
        // tagArrival() is trusted only if called at receipt: a tag obtained early and attached to a later frame carries
        // the earlier time. The engine cannot detect this; the frame-receipt code is inside the trusted computing base.
        SessionHarness h = harness(new SessionPolicy());
        h.session.start();
        FrameTag early = h.session.tagArrival();
        h.clock.advance(800);
        h.deliver(early, Kind.LIVE);
        assertNotNull(early);
        assertEquals(0, h.session.outcome().droppedStaleFrames, "accepted: no processing-delay bound exists");
    }

    // ================================================================ finding 4: certification on every path
    @Test
    void certificationIsCheckedOnlyAtStartAndRetriesCannotBypassIt() {
        SessionPolicy p = new SessionPolicy();
        p.requiredCertification = "L1";
        SessionHarness h = new SessionHarness(p, new AttemptLedger.InMemory(), verifier, "L0");
        expect(h.session.start(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
        expect(h.session.retry(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
        expect(h.session.recoverDevice(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
        expect(h.session.start(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
    }
}
