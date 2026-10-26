package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Decision-engine tests: every outcome path, with a fake clock, synthetic evidence ([SIM]) and a verifier double. The
 * binder itself is tested in CaptureBinderTest; signed end-to-end binding in SessionBindingIntegrationTest.
 * Invariant: only the positive path reaches VERIFIED; everything else fails closed.
 */
class LivenessSessionTest {
    static final byte[] RESP = "{}".getBytes(StandardCharsets.UTF_8);

    SessionHarness.StubVerifier verifier = new SessionHarness.StubVerifier();
    SessionHarness h = harness(new SessionPolicy(), null);

    SessionHarness harness(SessionPolicy p, String cert) {
        return new SessionHarness(p, new AttemptLedger.InMemory(), verifier, cert);
    }

    static BindingResult bound() {
        return BindingResult.of(Outcome.BOUND, BindingResult.Reason.OK, SessionHarness.HASH, SessionHarness.SUBJECT);
    }

    /** start → ready → capture with {@code during} live frames → response. */
    SessionOutcome capture(SessionHarness s, int during, BindingResult r) {
        s.session.start();
        assertEquals(State.READY_FOR_CAPTURE, s.untilReady());
        LivenessSession.CaptureRequest req = s.session.beginCapture();
        s.frames(during, Kind.LIVE);
        verifier.next = r;
        return s.session.onCaptureResponse(req.transactionId, RESP);
    }

    static void expect(SessionOutcome o, State st, Reason r) {
        assertEquals(st + "/" + r, o.state + "/" + o.reason, o.toString());
        if (st != State.VERIFIED) {
            assertNull(o.verifiedCaptureSha256, "hash only when VERIFIED");
        }
    }

    // ----------------------------------------------------------------------------------------------- positive
    @Test
    void liveStreamBoundCaptureAndCoveredWindowVerify() {
        SessionOutcome o = capture(h, 10, bound());
        expect(o, State.VERIFIED, Reason.OK);
        assertEquals(SessionHarness.HASH, o.verifiedCaptureSha256);
        assertEquals(1, o.attempt);
        // window handed to the binder: [request - latency, response] on the host wall clock (derived from mono)
        var ctx = verifier.seen.get(0);
        assertEquals(10 * 67 + 300, ctx.windowTo.toEpochMilli() - ctx.windowFrom.toEpochMilli());
        assertTrue(ctx.streamEmbeddings.size() >= 3);
    }

    @Test
    void verifiedSessionIgnoresEverythingAfterwards() {
        expect(capture(h, 10, bound()), State.VERIFIED, Reason.OK);
        h.frames(5, Kind.LIVE);
        h.session.onDeviceDisconnected("x");
        h.session.onEngineError(new RuntimeException());
        h.session.shutdown();
        h.clock.advance(1_000_000);
        expect(h.session.tick(), State.VERIFIED, Reason.OK);
        assertTrue(h.session.outcome().droppedStaleFrames >= 5);
    }

    // ----------------------------------------------------------------------------------------------- insufficient evidence / passive
    @Test
    void tooFewFramesTimesOutAsInsufficientEvidence() {
        h.session.start();
        h.frames(5, Kind.LIVE);
        h.frames(20, Kind.NO_FACE);
        h.clock.advance(11_000);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.INSUFFICIENT_EVIDENCE);
    }

    @Test
    void lowStreamPadNeverReadiesWithoutChallengeEngine() {
        h.pad = 0.5f;
        h.session.start();
        h.frames(60, Kind.LIVE);
        assertEquals(State.CAPTURING, h.session.state());
        h.clock.advance(11_000);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.PASSIVE_UNCERTAIN_NO_CHALLENGE);
    }

    @Test
    void streamPadAttackFramesRejectAsAttack() {
        h.pad = 0.1f;
        h.session.start();
        h.frames(3, Kind.LIVE);
        SessionOutcome o = h.session.outcome();
        expect(o, State.REJECTED_ATTACK, Reason.STREAM_PAD_ATTACK);
        assertEquals(1, o.attackEvents);
    }

    @Test
    void multipleFacesBlockReadiness() {
        h.session.start();
        for (int i = 0; i < 30; i++) {
            h.frames(1, Kind.LIVE);
            h.frames(1, Kind.MULTI);
        }
        assertEquals(State.CAPTURING, h.session.state());
        h.clock.advance(11_000);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.MULTIPLE_FACES);
    }

    @Test
    void invalidPadOutputIsNeverEvidence() {
        h.session.start();
        for (float bad : new float[] {Float.NaN, Float.POSITIVE_INFINITY, -0.1f, 1.5f}) {
            h.pad = bad;
            h.frames(1, Kind.LIVE);
        }
        assertEquals(4, h.session.outcome().invalidEvidence);
        assertEquals(State.CAPTURING, h.session.state());
    }

    // ----------------------------------------------------------------------------------------------- F3 static / frozen
    @Test
    void staticImageStreamNeverReadies() {
        h.session.start();
        h.frames(75, Kind.STATIC);
        assertEquals(State.CAPTURING, h.session.state());
        h.clock.advance(11_000);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.STATIC_REPLAY_SUSPECT);
    }

    @Test
    void staticSwapDuringCaptureWindowIsRejected() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(80, Kind.STATIC);   // > staticWindowMs of static frames before the response
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.STATIC_IN_WINDOW);
    }

    // ----------------------------------------------------------------------------------------------- finding 3: scene swap in window
    /** Moving stream → still only during RCAPTURE (≈ 1.5 s) → motion resumes; {@code resumeBeforeResponse} live frames
     *  arrive before the response is processed. */
    SessionOutcome stillOnlyDuringCapture(SessionPolicy p, int resumeBeforeResponse) {
        h = harness(p, null);
        h.session.start();
        assertEquals(State.READY_FOR_CAPTURE, h.untilReady());
        h.frames(30, Kind.LIVE);                       // ≈ 2 s more motion
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(22, Kind.STATIC);                     // ≈ 1.5 s still while the device captures
        h.frames(resumeBeforeResponse, Kind.LIVE);
        verifier.next = bound();
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, RESP);
        h.frames(10, Kind.LIVE);                       // motion continues afterwards (cannot change the decision)
        assertEquals(o.state, h.session.state());
        return o;
    }

    /** CHARACTERIZATION of a residual risk (not a desired outcome): the default rules do not detect the swap. */
    @Test
    void stillOnlyDuringCaptureIsNotDetectedByDefaultRules_residualRisk() {
        expect(stillOnlyDuringCapture(new SessionPolicy(), 0), State.VERIFIED, Reason.OK);
    }

    @Test
    void proposedCaptureWindowVariationRuleDetectsTheNaiveSwap() {
        SessionPolicy p = new SessionPolicy();
        p.requireVariationInCaptureWindow = true;
        expect(stillOnlyDuringCapture(p, 0), State.RETRY_PENDING, Reason.STATIC_IN_CAPTURE_WINDOW);
    }

    /** CHARACTERIZATION: resuming motion just before the response defeats the proposed rule too (residual risk). */
    @Test
    void proposedRuleIsBypassedIfMotionResumesBeforeTheResponse_residualRisk() {
        SessionPolicy p = new SessionPolicy();
        p.requireVariationInCaptureWindow = true;
        expect(stillOnlyDuringCapture(p, 3), State.VERIFIED, Reason.OK);
    }

    @Test
    void frozenFrameInWindowIsRejected() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(3, Kind.LIVE);
        h.frames(1, Kind.FROZEN);
        h.frames(3, Kind.LIVE);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.INTEGRITY_IN_WINDOW);
    }

    // ----------------------------------------------------------------------------------------------- temporal coverage
    @Test
    void streamPausedDuringCaptureIsAGap() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(2, Kind.LIVE);
        h.clock.advance(900);                    // stream pauses while the device captures
        h.frames(2, Kind.LIVE);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.STREAM_GAP_IN_WINDOW);
    }

    @Test
    void streamStoppedAtCaptureIsAGapAtTheWindowEnd() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(3, Kind.LIVE);
        h.clock.advance(800);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.STREAM_GAP_IN_WINDOW);
    }

    @Test
    void windowWithoutFramesIsNotCovered() {
        SessionPolicy p = new SessionPolicy();
        p.windowMaxGapMs = 10_000;               // isolate the coverage rule
        h = harness(p, null);
        h.session.start();
        h.untilReady();
        h.clock.advance(1_000);
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.clock.advance(50);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.WINDOW_NOT_COVERED);
    }

    @Test
    void attackLevelFrameInWindowIsAnAttack() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(3, Kind.LIVE);
        h.pad = 0.1f;
        h.frames(1, Kind.LIVE);
        h.pad = 0.95f;
        h.frames(3, Kind.LIVE);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.REJECTED_ATTACK, Reason.WINDOW_PAD_ATTACK);
    }

    @Test
    void lowPadInWindowIsInsufficient() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.pad = 0.6f;
        h.frames(10, Kind.LIVE);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.WINDOW_PAD_INSUFFICIENT);
    }

    // ----------------------------------------------------------------------------------------------- embeddings / F4 injection
    @Test
    void missingEmbeddingsInWindowFailClosed() {
        h.embed = false;                          // sampler produced nothing (slow, failed or dropped)
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.MISSING_EMBEDDINGS);
    }

    @Test
    void nonFrontalEmbeddingsDoNotCount() {
        h.yaw = 0.6f;
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.MISSING_EMBEDDINGS);
    }

    @Test
    void malformedEmbeddingsAreInvalidNotEvidence() {
        h.embed = false;
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        float[] nan = SessionHarness.unit(0);
        nan[3] = Float.NaN;
        float[][] bad = {nan, new float[64], new float[128], null};
        h.frames(10, Kind.LIVE);
        int n = h.tags.size();
        for (int i = 0; i < bad.length; i++) {
            h.session.onEmbedding(h.tags.get(n - bad.length + i), bad[i]);   // ascending seq: the gate drops reordering
        }
        assertEquals(4, h.session.outcome().invalidEvidence);
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.MISSING_EMBEDDINGS);
    }

    @Test
    void subjectChangeDuringAttemptIsAnAttack() {
        h.embedding = SessionHarness.OTHER;      // stream shows person B ...
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.embedding = SessionHarness.SUBJECT;    // ... then person A, whose capture is signed
        h.frames(10, Kind.LIVE);
        verifier.next = bound();
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, RESP);
        expect(o, State.REJECTED_ATTACK, Reason.SUBJECT_CHANGED);
        assertEquals(1, o.attackEvents);
    }

    /**
     * Finding 1 (review 2026-10-24): subject A early, subject B near the capture, enough B frames to evict every A record
     * from the bounded store while the capture window itself stays covered. Must not VERIFY.
     */
    SessionOutcome subjectSwapWithEviction(SessionPolicy p, int bFramesBeforeCapture) {
        h = harness(p, null);
        h.embedding = SessionHarness.OTHER;        // subject A on the stream
        h.session.start();
        assertEquals(State.READY_FOR_CAPTURE, h.untilReady());
        h.embedding = SessionHarness.SUBJECT;      // subject B (the one whose capture is signed)
        h.frames(bFramesBeforeCapture, Kind.LIVE); // READY held (no tick): A's records are evicted
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        verifier.next = bound();
        return h.session.onCaptureResponse(req.transactionId, RESP);
    }

    @Test
    void subjectChangeSurvivesEvidenceStoreEvictionByCount() {
        SessionPolicy p = new SessionPolicy();
        p.maxRecords = 80;                         // ~5.3 s at 15 fps: window and static window still fit
        p.readyTimeoutMs = 60_000;                 // READY long enough for 100 frames (timeouts are enforced per event)
        SessionOutcome o = subjectSwapWithEviction(p, 100);
        expect(o, State.REJECTED_ATTACK, Reason.SUBJECT_CHANGED);
    }

    @Test
    void subjectChangeSurvivesEvidenceStoreEvictionByAge() {
        SessionPolicy p = new SessionPolicy();
        p.maxRecordAgeMs = 25_000;
        p.readyTimeoutMs = 60_000;                 // let READY last long enough for A to age out (ticks not called anyway)
        SessionOutcome o = subjectSwapWithEviction(p, 450);   // ~30 s of B
        expect(o, State.REJECTED_ATTACK, Reason.SUBJECT_CHANGED);
    }

    @Test
    void streamSubjectDifferentFromCaptureIsAnAttack() {
        verifier.next = BindingResult.of(Outcome.BOUND, BindingResult.Reason.OK, SessionHarness.HASH, SessionHarness.OTHER);
        expect(capture(h, 10, verifier.next), State.REJECTED_ATTACK, Reason.SUBJECT_CHANGED);
    }

    // ----------------------------------------------------------------------------------------------- binder outcomes
    @Test
    void everyBinderOutcomeIsMappedFailClosed() {
        for (BindingResult.Reason r : BindingResult.Reason.values()) {
            if (r == BindingResult.Reason.OK) {
                continue;
            }
            for (Outcome out : new Outcome[] {Outcome.REJECTED, Outcome.UNCERTAIN, Outcome.ATTACK, Outcome.ERROR}) {
                verifier = new SessionHarness.StubVerifier();
                SessionHarness s = harness(new SessionPolicy(), null);
                SessionOutcome o = capture(s, 10, BindingResult.of(out, r, SessionHarness.HASH, SessionHarness.SUBJECT));
                assertTrue(o.state != State.VERIFIED, out + "/" + r + " -> " + o);
                assertNull(o.verifiedCaptureSha256);
                State want = out == Outcome.ERROR ? State.ERROR_ENGINE
                        : out == Outcome.UNCERTAIN ? State.RETRY_PENDING
                        : out == Outcome.ATTACK ? State.REJECTED_ATTACK : null;
                if (want != null) {
                    assertEquals(want, o.state, out + "/" + r);
                }
            }
        }
    }

    @Test
    void integrityRejectionsAreAttackEventsAndOthersRetry() {
        // attributable to the subject: subject attack events
        for (BindingResult.Reason r : new BindingResult.Reason[] {BindingResult.Reason.DEVICE_MISMATCH, BindingResult.Reason.SUBJECT_MISMATCH}) {
            verifier = new SessionHarness.StubVerifier();
            SessionOutcome o = capture(harness(new SessionPolicy(), null), 10, BindingResult.of(Outcome.REJECTED, r, null, null));
            expect(o, State.REJECTED_ATTACK, Reason.BINDING_INTEGRITY);
            assertEquals(1, o.attackEvents, r.name());
        }
        // not attributable (owner decision 2026-10-24): rejected security events counted against the channel
        for (BindingResult.Reason r : new BindingResult.Reason[] {BindingResult.Reason.BAD_SIGNATURE,
                BindingResult.Reason.UNTRUSTED_DEVICE, BindingResult.Reason.TRANSACTION_MISMATCH,
                BindingResult.Reason.REPLAYED_RESPONSE, BindingResult.Reason.DIGITAL_ID_INVALID, BindingResult.Reason.MALFORMED_RESPONSE}) {
            verifier = new SessionHarness.StubVerifier();
            SessionOutcome o = capture(harness(new SessionPolicy(), null), 10, BindingResult.of(Outcome.REJECTED, r, null, null));
            expect(o, State.REJECTED_ATTACK, Reason.CHANNEL_INTEGRITY);
            assertEquals(0, o.attackEvents, r.name());
            assertEquals(1, o.channelEvents, r.name());
        }
        for (BindingResult.Reason r : new BindingResult.Reason[] {BindingResult.Reason.DEVICE_ERROR,
                BindingResult.Reason.NO_FACE, BindingResult.Reason.BAD_BIO_FORMAT}) {
            verifier = new SessionHarness.StubVerifier();
            expect(capture(harness(new SessionPolicy(), null), 10, BindingResult.of(Outcome.REJECTED, r, null, null)),
                    State.RETRY_PENDING, Reason.BINDING_REJECTED);
        }
        // owner decision 2026-10-24: device faults are rejected without an attack event
        for (BindingResult.Reason r : new BindingResult.Reason[] {BindingResult.Reason.TRANSACTION_ABSENT,
                BindingResult.Reason.MALFORMED_CONTENT, BindingResult.Reason.CAPTURE_STALE,
                BindingResult.Reason.CAPTURE_FROM_FUTURE, BindingResult.Reason.CAPTURE_OUTSIDE_WINDOW}) {
            verifier = new SessionHarness.StubVerifier();
            SessionOutcome o = capture(harness(new SessionPolicy(), null), 10, BindingResult.of(Outcome.REJECTED, r, null, null));
            expect(o, State.RETRY_PENDING, Reason.DEVICE_FAULT);
            assertEquals(0, o.attackEvents, r.name());
        }
    }

    @Test
    void binderThrowingOrReturningNullOrIncompleteIsEngineError() {
        verifier.toThrow = new IllegalStateException("boom");
        expect(capture(h, 10, null), State.ERROR_ENGINE, Reason.ENGINE_ERROR);
        verifier = new SessionHarness.StubVerifier();
        expect(capture(harness(new SessionPolicy(), null), 10, null), State.ERROR_ENGINE, Reason.ENGINE_ERROR);
        verifier = new SessionHarness.StubVerifier();
        expect(capture(harness(new SessionPolicy(), null), 10,
                BindingResult.of(Outcome.BOUND, BindingResult.Reason.OK, SessionHarness.HASH, null)), State.ERROR_ENGINE, Reason.ENGINE_ERROR);
        verifier = new SessionHarness.StubVerifier();
        expect(capture(harness(new SessionPolicy(), null), 10,
                BindingResult.of(Outcome.BOUND, BindingResult.Reason.OK, null, SessionHarness.SUBJECT)), State.ERROR_ENGINE, Reason.ENGINE_ERROR);
    }

    // ----------------------------------------------------------------------------------------------- F1 replay / late responses
    @Test
    void responseForAnotherRequestIsIgnored() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        verifier.next = bound();
        SessionOutcome o = h.session.onCaptureResponse("not-" + req.transactionId, RESP);
        assertEquals(State.CAPTURE_IN_FLIGHT, o.state);
        assertEquals(1, o.ignoredLateResponses);
        o = h.session.onCaptureResponse(null, RESP);
        assertEquals(2, o.ignoredLateResponses);
        assertTrue(verifier.seen.isEmpty(), "ignored responses are never bound");
    }

    @Test
    void lateResponseAfterTimeoutAndRetryCannotVerify() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest old = h.session.beginCapture();
        h.clock.advance(16_000);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.CAPTURE_TIMEOUT);
        h.session.retry();
        h.untilReady();
        verifier.next = bound();
        SessionOutcome o = h.session.onCaptureResponse(old.transactionId, RESP);
        assertEquals(State.READY_FOR_CAPTURE, o.state);
        assertEquals(1, o.ignoredLateResponses);
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.session.onCaptureResponse(old.transactionId, RESP);
        assertEquals(State.CAPTURE_IN_FLIGHT, h.session.state());
        h.frames(10, Kind.LIVE);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.VERIFIED, Reason.OK);
        assertEquals(2, h.session.outcome().attempt);
    }

    @Test
    void secondResponseForSameRequestIsIgnored() {
        expect(capture(h, 10, bound()), State.VERIFIED, Reason.OK);
        SessionOutcome o = h.session.onCaptureResponse(verifier.seen.get(0).expectedTransactionId, RESP);
        assertEquals(1, o.ignoredLateResponses);
        assertEquals(1, verifier.seen.size());
    }

    @Test
    void nonceIsFreshPerCapture() {
        h.session.start();
        h.untilReady();
        String a = h.session.beginCapture().transactionId;
        h.clock.advance(16_000);
        h.session.tick();
        h.session.retry();
        h.untilReady();
        String b = h.session.beginCapture().transactionId;
        assertTrue(!a.equals(b) && a.length() >= 32);
    }

    // ----------------------------------------------------------------------------------------------- F2 stale evidence
    @Test
    void evidenceFromPreviousAttemptIsDropped() {
        h.session.start();
        h.frames(20, Kind.LIVE);
        FrameTag old = h.tags.get(h.tags.size() - 1);
        h.session.onDeviceDisconnected("unplug");
        h.session.recoverDevice();
        long before = h.session.outcome().droppedStaleFrames;
        h.deliver(old, Kind.LIVE);                   // old epoch
        assertEquals(before + 1, h.session.outcome().droppedStaleFrames);
        h.session.onEmbedding(old, SessionHarness.SUBJECT);
        assertTrue(h.session.outcome().droppedStaleEmbeddings >= 1);
    }

    @Test
    void frameReceivedBeforeAttemptStartIsDroppedEvenWithCurrentEpoch() {
        h.session.start();
        h.frames(5, Kind.LIVE);
        long lastTag = h.clock.mono;
        h.session.onDeviceDisconnected("x");
        h.clock.advance(5);
        h.session.recoverDevice();                  // freshness floor = lastTag + 5 ms
        h.clock.advance(10);
        // valid per the timestamp contract (after the last tag, 13 ms old, consistent wall) but received before the floor
        FrameTag t = h.session.tagArrival(1000, lastTag + 2_000_000L, h.clock.wall - 13);
        assertNotNull(t);
        long before = h.session.outcome().droppedStaleFrames;
        h.deliver(t, Kind.LIVE);
        assertEquals(before + 1, h.session.outcome().droppedStaleFrames);
    }

    // ----------------------------------------------------------------------------------------------- finding 2: timestamps
    @Test
    void trustedTagsComeFromTheSessionClockAndCounter() {
        h.session.start();
        h.clock.advance(40);
        FrameTag a = h.session.tagArrival();
        FrameTag b = h.session.tagArrival();
        assertEquals(h.clock.mono, a.monoNanos);
        assertEquals(h.clock.wall, a.wallMillis);
        assertTrue(b.seq > a.seq);
    }

    @Test
    void futureStaleNonMonotonicAndInconsistentTimestampsAreRejected() {
        h.session.start();
        h.frames(3, Kind.LIVE);
        long now = h.clock.mono, wall = h.clock.wall;
        // future
        assertNull(h.session.tagArrival(1, now + 1_000_000L, wall + 1));
        // stale (older than maxArrivalAgeMs = 1000)
        h.clock.advance(2_000);
        assertNull(h.session.tagArrival(2, h.clock.mono - 1_500_000_000L, h.clock.wall - 1_500));
        // non-monotonic: older than the last issued tag
        FrameTag ok = h.session.tagArrival(3, h.clock.mono - 100_000_000L, h.clock.wall - 100);
        assertNotNull(ok);
        assertNull(h.session.tagArrival(4, h.clock.mono - 200_000_000L, h.clock.wall - 200));
        // wall/mono inconsistent (wall claims a different instant than mono, beyond clockJumpToleranceMs)
        assertNull(h.session.tagArrival(5, h.clock.mono, h.clock.wall + 10_000));
        assertNull(h.session.tagArrival(6, h.clock.mono, h.clock.wall - 10_000));
        assertEquals(5, h.session.outcome().rejectedArrivalTimestamps);
        long stale = h.session.outcome().droppedStaleFrames;
        h.deliver(null, Kind.LIVE);                    // a rejected (null) tag is never evidence
        assertEquals(stale + 1, h.session.outcome().droppedStaleFrames);
    }

    @Test
    void timeoutsAreEnforcedWithoutTick() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.clock.advance(16_000);                      // capture timeout passed; tick() never called
        verifier.next = bound();
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, RESP);
        expect(o, State.RETRY_PENDING, Reason.CAPTURE_TIMEOUT);
        assertEquals(1, o.ignoredLateResponses);
        assertTrue(verifier.seen.isEmpty());
    }

    @Test
    void streamAttackFramesCountAcrossEviction() {
        SessionPolicy p = new SessionPolicy();
        p.maxRecords = 20;
        h = harness(p, null);
        h.session.start();
        h.pad = 0.1f;
        h.frames(2, Kind.LIVE);                       // two attack-level frames ...
        h.pad = 0.95f;
        h.frames(30, Kind.LIVE);                      // ... evicted from the store
        h.pad = 0.1f;
        h.frames(1, Kind.LIVE);                       // third one: the attempt-level count reaches attackMinFrames
        expect(h.session.outcome(), State.REJECTED_ATTACK, Reason.STREAM_PAD_ATTACK);
    }

    @Test
    void attemptSubjectLedgerOverflowFailsClosed() {
        SessionPolicy p = new SessionPolicy();
        p.maxAttemptEmbeddings = 5;
        h = harness(p, null);
        SessionOutcome o = capture(h, 10, bound());
        expect(o, State.RETRY_PENDING, Reason.ATTEMPT_EVIDENCE_OVERFLOW);
    }

    @Test
    void policyIsPinnedAtConstruction() {
        SessionPolicy p = new SessionPolicy();
        h = harness(p, "L0");
        p.requiredCertification = "L1";              // later mutation of the caller's object has no effect
        assertEquals(State.CAPTURING, h.session.start().state);
    }

    @Test
    void outOfOrderAndForeignSessionFramesAreDropped() {
        h.session.start();
        h.frames(5, Kind.LIVE);
        long before = h.session.outcome().droppedStaleFrames;
        h.deliver(h.tags.get(2), Kind.LIVE);          // replayed / reordered sequence number
        SessionHarness other = harness(new SessionPolicy(), null);
        other.session.start();
        other.frames(1, Kind.LIVE);
        h.deliver(new FrameTag(new byte[16], 1, 999, h.clock.mono, h.clock.wall), Kind.LIVE);
        h.deliver(new FrameTag(other.tags.get(0).sessionId, 1, 1000, h.clock.mono, h.clock.wall), Kind.LIVE);
        assertEquals(before + 3, h.session.outcome().droppedStaleFrames);
    }

    @Test
    void retryDiscardsAllPositiveEvidence() {
        h.session.start();
        h.untilReady();
        h.clock.advance(6_000);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.CAPTURE_NOT_STARTED);
        h.session.retry();
        assertEquals(State.CAPTURING, h.session.state());
        assertThrows(IllegalStateException.class, h.session::beginCapture);
        h.frames(3, Kind.LIVE);
        assertEquals(State.CAPTURING, h.session.state(), "readiness must be re-earned from new frames");
    }

    // ----------------------------------------------------------------------------------------------- F7 clocks
    @Test
    void wallClockJumpBeforeResponseFailsClosed() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        h.clock.wall += 3_600_000;                    // NTP step / manual change
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.CLOCK_DISCONTINUITY);
        assertTrue(verifier.seen.isEmpty(), "binding not attempted across a clock discontinuity");
        h.session.retry();                            // re-baselines
        h.untilReady();
        req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.VERIFIED, Reason.OK);
    }

    @Test
    void backwardWallJumpAlsoFailsClosedAndSmallDriftIsTolerated() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        h.clock.wall -= 5_000;
        verifier.next = bound();
        expect(h.session.onCaptureResponse(req.transactionId, RESP), State.RETRY_PENDING, Reason.CLOCK_DISCONTINUITY);

        SessionHarness s = harness(new SessionPolicy(), null);
        verifier.next = bound();
        s.session.start();
        s.untilReady();
        req = s.session.beginCapture();
        s.frames(10, Kind.LIVE);
        s.clock.wall += 500;                          // within clockJumpToleranceMs
        expect(s.session.onCaptureResponse(req.transactionId, RESP), State.VERIFIED, Reason.OK);
    }

    @Test
    void windowBoundsUseMonotonicDurationsNotTheJumpedWallClock() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        long reqWall = h.clock.wall;
        h.frames(10, Kind.LIVE);
        h.clock.wall += 1_500;                        // tolerated drift; bounds must still be request-wall + mono elapsed
        verifier.next = bound();
        h.session.onCaptureResponse(req.transactionId, RESP);
        var ctx = verifier.seen.get(0);
        assertEquals(reqWall - 300, ctx.windowFrom.toEpochMilli());
        assertEquals(reqWall + 670, ctx.windowTo.toEpochMilli());
        assertEquals(ctx.windowTo, verifier.nows.get(0));
    }

    // ----------------------------------------------------------------------------------------------- timeouts / lifecycle
    @Test
    void timeoutsFailClosed() {
        h.session.start();
        h.untilReady();
        h.clock.advance(5_001);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.CAPTURE_NOT_STARTED);
        h.session.retry();
        h.untilReady();
        h.session.beginCapture();
        h.clock.advance(15_001);
        expect(h.session.tick(), State.RETRY_PENDING, Reason.CAPTURE_TIMEOUT);
    }

    @Test
    void sessionTtlExpires() {
        h.session.start();
        h.untilReady();
        h.session.beginCapture();
        h.clock.advance(121_000);
        expect(h.session.tick(), State.EXPIRED, Reason.SESSION_EXPIRED);
        h.frames(3, Kind.LIVE);
        assertEquals(State.EXPIRED, h.session.state());
    }

    @Test
    void shutdownAndCancelDuringCaptureAreTerminal() {
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        expect(h.session.shutdown(), State.SHUTDOWN, Reason.SHUTDOWN);
        verifier.next = bound();
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, RESP);
        expect(o, State.SHUTDOWN, Reason.SHUTDOWN);
        assertEquals(1, o.ignoredLateResponses);
        assertTrue(verifier.seen.isEmpty());
        expect(h.session.retry(), State.SHUTDOWN, Reason.SHUTDOWN);

        SessionHarness c = harness(new SessionPolicy(), null);
        c.session.start();
        c.untilReady();
        expect(c.session.cancel(), State.CANCELLED, Reason.CANCELLED);
        assertThrows(IllegalStateException.class, c.session::beginCapture);
        c.session.close();
        assertEquals(State.CANCELLED, c.session.state());
    }

    @Test
    void engineErrorIsTerminal() {
        h.session.start();
        h.frames(5, Kind.LIVE);
        h.session.onEngineError(new OutOfMemoryError());
        expect(h.session.outcome(), State.ERROR_ENGINE, Reason.ENGINE_ERROR);
        expect(h.session.retry(), State.ERROR_ENGINE, Reason.ENGINE_ERROR);
    }

    @Test
    void operationsBeforeStartAreInert() {
        h.frames(30, Kind.LIVE);
        assertEquals(State.CREATED, h.session.state());
        assertThrows(IllegalStateException.class, h.session::beginCapture);
        assertEquals(State.CREATED, h.session.tick().state);
    }

    // ----------------------------------------------------------------------------------------------- device trust / limits
    @Test
    void certificationLevelPolicyIsEnforced() {
        SessionPolicy p = new SessionPolicy();
        p.requiredCertification = "L1";
        expect(harness(p, "L0").session.start(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
        expect(harness(p, null).session.start(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
        assertEquals(State.CAPTURING, harness(p, "L1").session.start().state);
        p.requiredCertification = "L0";
        expect(harness(p, "unknown").session.start(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
        assertEquals(State.CAPTURING, harness(p, "L0").session.start().state);
    }

    @Test
    void unknownConfiguredCertificationLevelIsRejected() {
        for (String bad : new String[] {"L2", "l1", " L1", "", "LO", "any", "L1 "}) {
            SessionPolicy p = new SessionPolicy();
            p.requiredCertification = bad;
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> harness(p, "L1"),
                    "accepted " + bad);
            assertTrue(e.getMessage().contains("requiredCertification"));
        }
    }

    @Test
    void otherInvalidPolicyValuesAreRejected() {
        java.util.List<java.util.function.Consumer<SessionPolicy>> bad = java.util.Arrays.asList(
                q -> q.streamAttack = 0.9f,               // attack >= accept
                q -> q.streamAccept = Float.NaN,
                q -> q.subjectMinCosine = 0f,
                q -> q.maxAttempts = 0,
                q -> q.captureTimeoutMs = 0,
                q -> q.maxRecordAgeMs = 4_000,            // shorter than the static window
                q -> q.maxRecords = 3,
                q -> q.clockJumpToleranceMs = 0);
        for (java.util.function.Consumer<SessionPolicy> b : bad) {
            SessionPolicy p = new SessionPolicy();
            b.accept(p);
            assertThrows(IllegalArgumentException.class, () -> harness(p, null));
        }
    }

    @Test
    void deviceCertificationValuesAreMatchedExactly() {
        SessionPolicy p = new SessionPolicy();
        p.requiredCertification = "L1";
        for (String dev : new String[] {"l1", "L1 ", "L2", ""}) {
            expect(harness(p, dev).session.start(), State.FAILED_POLICY, Reason.DEVICE_LEVEL_INSUFFICIENT);
        }
    }

    @Test
    void deviceDisconnectRecoveryIsBoundedAndDoesNotConsumeAttempts() {
        h.session.start();
        for (int i = 0; i < 2; i++) {
            h.frames(3, Kind.LIVE);
            h.session.onDeviceDisconnected("unplug");
            expect(h.session.outcome(), State.ERROR_DEVICE, Reason.DEVICE_DISCONNECTED);
            assertEquals(State.CAPTURING, h.session.recoverDevice().state);
        }
        assertEquals(1, h.session.outcome().attempt);
        h.session.onDeviceDisconnected("unplug");
        expect(h.session.recoverDevice(), State.FAILED_MAX_RETRIES, Reason.DEVICE_RECOVERY_LIMIT);
    }

    @Test
    void retryLimitAndAttackLimitAreEnforcedAcrossSessions() {
        AttemptLedger ledger = new AttemptLedger.InMemory();
        SessionHarness s = new SessionHarness(new SessionPolicy(), ledger, verifier, null);
        s.session.start();
        for (int i = 0; i < 2; i++) {
            s.clock.advance(11_000);
            s.session.tick();
            s.session.retry();
        }
        assertEquals(3, s.session.outcome().attempt);
        s.clock.advance(11_000);
        s.session.tick();
        expect(s.session.retry(), State.FAILED_MAX_RETRIES, Reason.MAX_RETRIES);
        // a new session for the same subject cannot reset the counter
        expect(new SessionHarness(new SessionPolicy(), ledger, verifier, null).session.start(), State.FAILED_MAX_RETRIES,
                Reason.MAX_RETRIES);

        AttemptLedger l2 = new AttemptLedger.InMemory();
        SessionHarness a = new SessionHarness(new SessionPolicy(), l2, verifier, null);
        a.pad = 0.1f;
        a.session.start();
        a.frames(3, Kind.LIVE);
        assertEquals(State.REJECTED_ATTACK, a.session.state());
        assertEquals(State.CAPTURING, a.session.retry().state);   // first attack event tolerated (maxAttackEvents=1)
        a.frames(3, Kind.LIVE);
        expect(a.session.retry(), State.FAILED_MAX_RETRIES, Reason.ATTACK_LIMIT);
        expect(new SessionHarness(new SessionPolicy(), l2, verifier, null).session.start(), State.FAILED_MAX_RETRIES,
                Reason.ATTACK_LIMIT);
    }

    @Test
    void outcomeCarriesNoBiometricData() {
        expect(capture(h, 10, bound()), State.VERIFIED, Reason.OK);
        String s = h.session.outcome().toString();
        assertTrue(!s.contains(Arrays.toString(SessionHarness.SUBJECT)));
        assertNotNull(h.session.outcome().verifiedCaptureSha256);
    }
}
