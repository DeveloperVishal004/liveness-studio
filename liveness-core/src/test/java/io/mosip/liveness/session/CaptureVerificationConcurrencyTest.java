package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Capture-lock refactor: the binder/B1 verification runs WITHOUT the session lock (phase B). A latch holds the verifier
 * inside phase B while the test acts. Checked: frames are tagged with fresh timestamps and processed during verification
 * (no blocking), and anything that supersedes the capture during verification wins: the late result is discarded,
 * never applied, and never overwrites a terminal state. [CODE]
 */
class CaptureVerificationConcurrencyTest {
    static final byte[] RESP = "{}".getBytes(StandardCharsets.UTF_8);

    /** Verifier that blocks in phase B until released, then returns the configured result (or throws). */
    static final class BlockingVerifier implements CaptureVerifier {
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final AtomicInteger calls = new AtomicInteger();
        volatile BindingResult result = BindingResult.of(Outcome.BOUND, BindingResult.Reason.OK, SessionHarness.HASH, SessionHarness.SUBJECT);
        volatile RuntimeException toThrow;

        @Override
        public BindingResult bind(byte[] response, CaptureBinder.SessionContext ctx, Instant now) {
            calls.incrementAndGet();
            entered.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (toThrow != null) {
                throw toThrow;
            }
            return result;
        }
    }

    final BlockingVerifier verifier = new BlockingVerifier();
    final SessionHarness h = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), verifier, null);
    final AtomicReference<SessionOutcome> asyncOutcome = new AtomicReference<>();

    /** Ready, capture issued, 10 window frames, response delivered on another thread that blocks in the verifier. */
    Thread respondAsync() throws Exception {
        h.session.start();
        assertEquals(State.READY_FOR_CAPTURE, h.untilReady());
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        Thread t = new Thread(() -> asyncOutcome.set(h.session.onCaptureResponse(req.transactionId, RESP)), "capture-response");
        t.start();
        assertTrue(verifier.entered.await(5, TimeUnit.SECONDS), "verifier not reached");
        h.lastTxn = req.transactionId;
        return t;
    }

    SessionOutcome finish(Thread t) throws Exception {
        verifier.release.countDown();
        t.join(5_000);
        return h.session.outcome();
    }

    static void assertNotVerified(SessionOutcome o) {
        assertTrue(o.state != State.VERIFIED, o.toString());
        assertNull(o.verifiedCaptureSha256);
    }

    @Test
    void framesAreTaggedFreshAndProcessedWhileTheCaptureIsVerified() throws Exception {
        Thread t = respondAsync();
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {        // would deadlock if the lock were held
            for (int i = 0; i < 20; i++) {
                h.frames(1, Kind.LIVE);
                FrameTag last = h.tags.get(h.tags.size() - 1);
                assertEquals(h.clock.mono, last.monoNanos, "receipt timestamp must be taken at receipt");
            }
            assertEquals(State.CAPTURE_IN_FLIGHT, h.session.tick().state);
        });
        SessionOutcome o = finish(t);
        assertEquals(State.VERIFIED, o.state, o.toString());
    }

    @Test
    void cancelDuringVerificationWins() throws Exception {
        Thread t = respondAsync();
        assertEquals(State.CANCELLED, h.session.cancel().state);
        SessionOutcome o = finish(t);
        assertEquals(State.CANCELLED, o.state, o.toString());
        assertNotVerified(o);
        assertEquals(1, o.ignoredLateResponses);
    }

    @Test
    void shutdownDuringVerificationWinsEvenIfTheVerifierThrows() throws Exception {
        Thread t = respondAsync();
        verifier.toThrow = new IllegalStateException("binder crashed after shutdown");
        h.session.shutdown();
        SessionOutcome o = finish(t);
        assertEquals(State.SHUTDOWN, o.state, "a late failure must not overwrite a terminal state: " + o);
    }

    @Test
    void expiryDuringVerificationWins() throws Exception {
        Thread t = respondAsync();
        h.clock.advance(121_000);
        assertEquals(State.EXPIRED, h.session.tick().state);
        SessionOutcome o = finish(t);
        assertEquals(State.EXPIRED, o.state, o.toString());
        assertNotVerified(o);
    }

    @Test
    void deviceLossAndRecoveryDuringVerificationDiscardTheOldResult() throws Exception {
        Thread t = respondAsync();
        h.session.onDeviceDisconnected("usb");
        assertEquals(State.CAPTURING, h.session.recoverDevice().state);     // new epoch, same attempt count
        SessionOutcome o = finish(t);
        assertEquals(State.CAPTURING, o.state, "old result must not land in the new epoch: " + o);
        assertNotVerified(o);
        assertEquals(1, o.ignoredLateResponses);
    }

    @Test
    void streamAttackDuringVerificationWins() throws Exception {
        Thread t = respondAsync();
        h.pad = 0.1f;
        h.frames(3, Kind.LIVE);                                         // evaluated while the binder runs
        assertEquals(State.REJECTED_ATTACK, h.session.state());
        SessionOutcome o = finish(t);
        assertEquals(State.REJECTED_ATTACK, o.state, o.toString());
        assertEquals(Reason.STREAM_PAD_ATTACK, o.reason);
        assertNotVerified(o);
    }

    @Test
    void duplicateResponseDuringVerificationIsRejectedWithoutBlocking() throws Exception {
        Thread t = respondAsync();
        SessionOutcome dup = assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> h.session.onCaptureResponse(h.lastTxn, RESP));
        assertEquals(1, dup.ignoredLateResponses);
        SessionOutcome o = finish(t);
        assertEquals(State.VERIFIED, o.state, o.toString());
        assertEquals(1, verifier.calls.get(), "the duplicate never reached the verifier");
    }

    @Test
    void captureTimeoutDoesNotFireOnAResponseAlreadyReceived() throws Exception {
        Thread t = respondAsync();
        h.clock.advance(16_000);                                        // beyond captureTimeoutMs, below TTL
        assertEquals(State.CAPTURE_IN_FLIGHT, h.session.tick().state, "the response arrived in time; no NPE, no timeout");
        SessionOutcome o = finish(t);
        assertEquals(State.VERIFIED, o.state, o.toString());
    }

    @Test
    void verifierFailureStillFailsClosedWhenNothingSupersededIt() throws Exception {
        Thread t = respondAsync();
        verifier.toThrow = new IllegalStateException("decoder crash");
        SessionOutcome o = finish(t);
        assertEquals(State.ERROR_ENGINE, o.state, o.toString());
    }

    @Test
    void lateResultCannotVerifyANewAttempt() throws Exception {
        Thread t = respondAsync();
        h.session.onDeviceDisconnected("usb");
        h.session.recoverDevice();
        h.untilReady();
        LivenessSession.CaptureRequest req2 = h.session.beginCapture();
        SessionOutcome mid = finish(t);                                 // old result arrives during the NEW capture
        assertEquals(State.CAPTURE_IN_FLIGHT, mid.state, mid.toString());
        assertNull(mid.verifiedCaptureSha256);
        h.frames(10, Kind.LIVE);
        SessionOutcome own = h.session.onCaptureResponse(req2.transactionId, RESP);    // the new attempt's own response
        assertEquals(State.VERIFIED, own.state, own.toString());
        assertEquals(2, verifier.calls.get());
    }
}
