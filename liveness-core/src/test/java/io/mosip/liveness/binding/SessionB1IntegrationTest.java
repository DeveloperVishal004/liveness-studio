package io.mosip.liveness.binding;

import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionHarness;
import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import io.mosip.liveness.session.SessionPolicy;
import io.mosip.liveness.streamauth.StreamAuthResult;
import io.mosip.liveness.streamauth.StreamAuthenticator;
import io.mosip.liveness.streamauth.StreamDigestVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Random;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B1 prototype through the decision engine: real CaptureBinder (conservative gate, unchanged), real RS256 test keys,
 * synthetic frames. [CODE]. Invariants: an authentication failure never yields VERIFIED, is reported as
 * STREAM_AUTH_PROTOCOL_FAILURE / STREAM_AUTH_INTEGRITY_FAILURE (never as an attack/PAD verdict, no attack event), and
 * the default mode reports stream evidence as unauthenticated.
 */
class SessionB1IntegrationTest {
    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
    }

    final CaptureBinder binder = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
            CaptureBinderTest.stub(1, 0.95f, SessionHarness.SUBJECT), new CaptureBinder.Policy());
    final StreamDigestVerifier b1 = new StreamDigestVerifier(CaptureBinderTest.verifier);

    static SessionPolicy b1Policy() {
        SessionPolicy p = new SessionPolicy();
        p.requireStreamAuthentication = true;
        return p;
    }

    SessionHarness harness(StreamAuthenticator auth) {
        return new SessionHarness(auth == null ? new SessionPolicy() : b1Policy(), new AttemptLedger.InMemory(), binder, "L0", auth);
    }

    /** One attempt: ready, capture, 10 frames, response with a statement built from the device's emitted frames. */
    static SessionOutcome attempt(SessionHarness h, Consumer<SessionHarness> duringCapture, Consumer<B1Fixture> editStatement,
                                  boolean attachStatement) throws Exception {
        if (h.session.state() == State.CREATED) {
            h.session.start();
        } else {
            h.session.retry();
        }
        assertEquals(State.READY_FOR_CAPTURE, h.untilReady());
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        duringCapture.accept(h);
        h.frames(10, Kind.LIVE);
        long deviceNow = h.clock.wall;
        byte[] resp = CaptureBinderTest.response(c -> { c.txn = req.transactionId; c.ts = Instant.ofEpochMilli(deviceNow - 200); });
        if (attachStatement) {
            B1Fixture fx = new B1Fixture(req.transactionId);
            for (int i = 0; i < h.sentFrames.size(); i++) {
                fx.emit(h.sentFrames.get(i), h.sentTimes.get(i));
            }
            fx.issuedAt = Instant.ofEpochMilli(deviceNow);
            editStatement.accept(fx);
            resp = fx.attach(resp);
        }
        return h.session.onCaptureResponse(req.transactionId, resp);
    }

    static SessionOutcome attempt(SessionHarness h, Consumer<SessionHarness> duringCapture, Consumer<B1Fixture> edit) throws Exception {
        return attempt(h, duringCapture, edit, true);
    }

    static void expectAuthFailure(SessionOutcome o, Reason r, StreamAuthResult.Reason vr) {
        assertEquals(State.RETRY_PENDING + "/" + r, o.state + "/" + o.reason, o.toString());
        assertEquals(vr.outcome() + "/" + vr, o.streamAuthResult);
        assertEquals(0, o.attackEvents, "an authentication failure is not an attack verdict");
        assertNull(o.verifiedCaptureSha256);
        assertFalse(o.streamAuthenticated);
    }

    // ================================================================ positive and default mode
    @Test
    void authenticatedStreamVerifiesAndSaysSo() throws Exception {
        SessionOutcome o = attempt(harness(b1), h -> { }, f -> { });
        assertEquals(State.VERIFIED, o.state, o.toString());
        assertTrue(o.streamAuthenticated);
        assertEquals("AUTHENTICATED/OK", o.streamAuthResult);
    }

    @Test
    void defaultModeVerifiesButReportsTheStreamAsUnauthenticated() throws Exception {
        SessionOutcome o = attempt(harness(null), h -> { }, f -> { }, false);
        assertEquals(State.VERIFIED, o.state, o.toString());
        assertFalse(o.streamAuthenticated, "unsigned stream evidence stays explicitly unauthenticated");
        assertNull(o.streamAuthResult);
    }

    @Test
    void requiringAuthenticationWithoutAnAuthenticatorIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> new SessionHarness(b1Policy(), new AttemptLedger.InMemory(), binder, "L0"));
    }

    // ================================================================ negative attack tests (engine level)
    @Test
    void missingStatementIsAProtocolFailure() throws Exception {
        expectAuthFailure(attempt(harness(b1), h -> { }, f -> { }, false), Reason.STREAM_AUTH_PROTOCOL_FAILURE,
                StreamAuthResult.Reason.STATEMENT_MISSING);
    }

    @Test
    void framesInjectedDuringCaptureAreAnIntegrityFailure() throws Exception {
        expectAuthFailure(attempt(harness(b1), h -> {
            int[] n = {0};
            h.wire = x -> n[0]++ < 3 ? ("injected-" + n[0]).getBytes(StandardCharsets.US_ASCII) : x;
        }, f -> { }), Reason.STREAM_AUTH_INTEGRITY_FAILURE, StreamAuthResult.Reason.FRAME_NOT_COVERED);
    }

    @Test
    void samePersonVideoReplacingTheWholeStreamIsAnIntegrityFailure() throws Exception {
        SessionHarness h = harness(b1);
        int[] n = {0};
        h.wire = x -> ("attacker-video-" + n[0]++).getBytes(StandardCharsets.US_ASCII);   // T17: every frame replaced
        expectAuthFailure(attempt(h, x -> { }, f -> { }), Reason.STREAM_AUTH_INTEGRITY_FAILURE,
                StreamAuthResult.Reason.FRAME_NOT_COVERED);
    }

    @Test
    void replayedEarlierGenuineFramesAreAnIntegrityFailure() throws Exception {
        expectAuthFailure(attempt(harness(b1), h -> {
            byte[] old = h.sentFrames.get(5);
            int[] n = {0};
            h.wire = x -> n[0]++ < 2 ? old : x;                                         // loop an earlier genuine frame
        }, f -> { }), Reason.STREAM_AUTH_INTEGRITY_FAILURE, StreamAuthResult.Reason.FRAME_REORDERED);
    }

    @Test
    void suppressedWindowFramesAreAProtocolFailure() throws Exception {
        expectAuthFailure(attempt(harness(b1), h -> {
            int[] n = {0};
            h.wire = x -> (n[0]++ % 2 == 0) ? null : x;                                 // drop every other frame
        }, f -> { }), Reason.STREAM_AUTH_PROTOCOL_FAILURE, StreamAuthResult.Reason.MISSING_FRAMES_IN_WINDOW);
    }

    @Test
    void statementFromAnotherSessionIsRejected() throws Exception {
        // obtained in another session = signed for that session's RCAPTURE transaction
        expectAuthFailure(attempt(harness(b1), x -> { }, f -> f.txn = java.util.UUID.randomUUID().toString()),
                Reason.STREAM_AUTH_INTEGRITY_FAILURE, StreamAuthResult.Reason.WRONG_TRANSACTION);
    }

    @Test
    void delayedAuthenticStreamIsAProtocolFailure() throws Exception {
        expectAuthFailure(attempt(harness(b1), x -> { }, f -> f.times.replaceAll(t -> t - 10_000)),
                Reason.STREAM_AUTH_PROTOCOL_FAILURE, StreamAuthResult.Reason.STALE_FRAMES);
    }

    @Test
    void statementForAnotherTransactionIsRejected() throws Exception {
        expectAuthFailure(attempt(harness(b1), h -> { }, f -> f.txn = "previous-attempt-txn"), Reason.STREAM_AUTH_INTEGRITY_FAILURE,
                StreamAuthResult.Reason.WRONG_TRANSACTION);
    }

    @Test
    void forgedOrForeignSignaturesAreRejected() throws Exception {
        expectAuthFailure(attempt(harness(b1), h -> { }, f -> f.tamper = true), Reason.STREAM_AUTH_INTEGRITY_FAILURE,
                StreamAuthResult.Reason.BAD_SIGNATURE);
        expectAuthFailure(attempt(harness(b1), h -> { }, f -> {
            f.key = CaptureBinderTest.rogueKey;
            f.chain = new java.security.cert.X509Certificate[] {CaptureBinderTest.rogueCert};
        }), Reason.STREAM_AUTH_INTEGRITY_FAILURE, StreamAuthResult.Reason.UNTRUSTED_SIGNER);
    }

    @Test
    void framesTaggedWithoutBytesCannotBeAuthenticated() throws Exception {
        SessionHarness h = harness(b1);
        h.session.start();
        h.b1 = false;                                     // a receipt path that does not hash frames
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        long deviceNow = h.clock.wall;
        B1Fixture fx = new B1Fixture(req.transactionId);
        fx.issuedAt = Instant.ofEpochMilli(deviceNow);
        byte[] resp = fx.attach(CaptureBinderTest.response(c -> { c.txn = req.transactionId; c.ts = Instant.ofEpochMilli(deviceNow - 200); }));
        expectAuthFailure(h.session.onCaptureResponse(req.transactionId, resp), Reason.STREAM_AUTH_INTEGRITY_FAILURE,
                StreamAuthResult.Reason.UNHASHED_FRAME);
    }

    @Test
    void authenticatorFaultsFailClosedAsEngineErrors() throws Exception {
        SessionHarness t = harness((r, c, n) -> { throw new IllegalStateException("boom"); });
        assertEquals(State.ERROR_ENGINE, attempt(t, h -> { }, f -> { }).state);
        SessionHarness nul = harness((r, c, n) -> null);
        assertEquals(State.ERROR_ENGINE, attempt(nul, h -> { }, f -> { }).state);
    }

    @Test
    void authenticationFailureThenGenuineRetryVerifiesOnlyWithFreshAuthenticatedEvidence() throws Exception {
        SessionHarness h = harness(b1);
        expectAuthFailure(attempt(h, x -> { }, f -> f.tamper = true), Reason.STREAM_AUTH_INTEGRITY_FAILURE,
                StreamAuthResult.Reason.BAD_SIGNATURE);
        h.wire = java.util.function.UnaryOperator.identity();
        SessionOutcome o = attempt(h, x -> { }, f -> { });
        assertEquals(State.VERIFIED, o.state, o.toString());
        assertTrue(o.streamAuthenticated);
        assertEquals(2, o.attempt);
    }

    /** Random B1 failure modes (seeded): never VERIFIED, never an attack event caused by authentication. */
    @Test
    void randomAuthenticationFailuresNeverVerify() throws Exception {
        Random rnd = new Random(11);
        for (int i = 0; i < 40; i++) {
            int mode = rnd.nextInt(7);
            SessionHarness h = harness(b1);
            SessionOutcome o = attempt(h, x -> {
                int[] n = {0};
                if (mode == 0) x.wire = y -> n[0]++ == 1 ? "x".getBytes() : y;
                if (mode == 1) x.wire = y -> n[0]++ % 3 == 0 ? null : y;
            }, f -> {
                if (mode == 2) f.tamper = true;
                if (mode == 3) f.times.replaceAll(t -> t - 30_000);
                if (mode == 4) f.txn = "other";
                if (mode == 5) f.issuedAt = f.issuedAt.minusSeconds(120);
                if (mode == 6) f.captureDataOverride = "x.y.z";
            });
            assertNotEquals(State.VERIFIED, o.state, "mode " + mode + ": " + o);
            assertEquals(0, o.attackEvents, "mode " + mode + ": " + o);
            assertTrue(o.reason == Reason.STREAM_AUTH_PROTOCOL_FAILURE || o.reason == Reason.STREAM_AUTH_INTEGRITY_FAILURE,
                    "mode " + mode + ": " + o);
        }
    }
}
