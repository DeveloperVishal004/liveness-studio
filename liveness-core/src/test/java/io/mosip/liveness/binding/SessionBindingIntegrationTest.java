package io.mosip.liveness.binding;

import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionHarness;
import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import io.mosip.liveness.session.SessionPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Decision engine + real {@link CaptureBinder}: RS256 JWS responses signed with the mock device's TEST-ONLY keys, the
 * session's own nonce and the session's capture window. The capture analyzer is stubbed (vision is not under test).
 * Covers F1 (replay), F6 (device trust) and F7 (timestamp formats / skew) end to end through the engine.
 * Evidence class: [CODE] — no real device, no PAD-accuracy claim.
 */
class SessionBindingIntegrationTest {
    static X509Certificate expiredCert;

    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
        expiredCert = CaptureBinderTest.cert("/keys/expired.pem");
    }

    final CaptureBinder binder = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
            CaptureBinderTest.stub(1, 0.95f, SessionHarness.SUBJECT), new CaptureBinder.Policy());

    SessionHarness harness(AttemptLedger ledger) {
        return new SessionHarness(new SessionPolicy(), ledger, binder, "L0");
    }

    /** Runs one attempt; {@code edit} may change the signed capture, given the request and the device's "now". */
    static SessionOutcome attempt(SessionHarness h, BiConsumer<CaptureBinderTest.Capture, LivenessSession.CaptureRequest> edit)
            throws Exception {
        return attempt(h, edit, x -> x.frames(10, Kind.LIVE));
    }

    /** As above, with custom stream evidence during the capture window. */
    static SessionOutcome attempt(SessionHarness h, BiConsumer<CaptureBinderTest.Capture, LivenessSession.CaptureRequest> edit,
                                  java.util.function.Consumer<SessionHarness> duringCapture) throws Exception {
        if (h.session.state() == State.CREATED) {
            h.session.start();
        } else {
            h.session.retry();
        }
        assertEquals(State.READY_FOR_CAPTURE, h.untilReady());
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        duringCapture.accept(h);
        long deviceNow = h.clock.wall;
        byte[] resp = CaptureBinderTest.response(c -> {
            c.txn = req.transactionId;
            c.ts = Instant.ofEpochMilli(deviceNow - 200);
            edit.accept(c, req);
        });
        return h.session.onCaptureResponse(req.transactionId, resp);
    }

    static void expect(SessionOutcome o, State s, Reason r, BindingResult.Reason br) {
        assertEquals(s + "/" + r + "/" + br, o.state + "/" + o.reason + "/" + o.bindingReason, o.toString());
        if (s != State.VERIFIED) {
            assertNull(o.verifiedCaptureSha256);
        }
    }

    @Test
    void signedFreshNonceBoundCaptureVerifies() throws Exception {
        SessionOutcome o = attempt(harness(new AttemptLedger.InMemory()), (c, r) -> { });
        expect(o, State.VERIFIED, Reason.OK, BindingResult.Reason.OK);
        assertEquals(64, o.verifiedCaptureSha256.length());
    }

    // ------------------------------------------------------------------ F1 replay
    @Test
    void replayOfAPreviouslySignedResponseIsRejected() throws Exception {
        SessionHarness h = harness(new AttemptLedger.InMemory());
        byte[][] first = new byte[1][];
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        first[0] = CaptureBinderTest.response(c -> { c.txn = req.transactionId; c.ts = Instant.ofEpochMilli(h.clock.wall); });
        h.session.onDeviceDisconnected("x");          // attempt aborted before the response is used
        h.session.recoverDevice();
        h.untilReady();
        LivenessSession.CaptureRequest req2 = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        // attacker answers the new request with the old (validly signed) response
        expect(h.session.onCaptureResponse(req2.transactionId, first[0]), State.REJECTED_ATTACK, Reason.CHANNEL_INTEGRITY,
                BindingResult.Reason.TRANSACTION_MISMATCH);
    }

    @Test
    void byteIdenticalReplayAfterVerificationIsRejectedInANewSession() throws Exception {
        AttemptLedger ledger = new AttemptLedger.InMemory();
        SessionHarness a = harness(ledger);
        byte[][] captured = new byte[1][];
        a.session.start();
        a.untilReady();
        LivenessSession.CaptureRequest req = a.session.beginCapture();
        a.frames(10, Kind.LIVE);
        captured[0] = CaptureBinderTest.response(c -> { c.txn = req.transactionId; c.ts = Instant.ofEpochMilli(a.clock.wall); });
        expect(a.session.onCaptureResponse(req.transactionId, captured[0]), State.VERIFIED, Reason.OK, BindingResult.Reason.OK);
        // second session, same binder (replay cache), attacker controls the transport and echoes the nonce check away:
        SessionHarness b = harness(new AttemptLedger.InMemory());
        b.session.start();
        b.untilReady();
        LivenessSession.CaptureRequest req2 = b.session.beginCapture();
        b.frames(10, Kind.LIVE);
        SessionOutcome o = b.session.onCaptureResponse(req2.transactionId, captured[0]);
        assertEquals(State.REJECTED_ATTACK, o.state);
        assertEquals(Reason.CHANNEL_INTEGRITY, o.reason);
    }

    // ------------------------------------------------------------------ temporal binding at the signature level
    @Test
    void signedTimestampOutsideTheCaptureWindowIsRejected() throws Exception {
        // inside the session (not stale) but 30 s before the RCAPTURE request: captured earlier, released later
        // nonce matched, so the time error is a device-clock fault (owner decision 2026-10-24): rejected, no attack event
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.ts = c.ts.minusSeconds(30)),
                State.RETRY_PENDING, Reason.DEVICE_FAULT, BindingResult.Reason.CAPTURE_OUTSIDE_WINDOW);
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.ts = c.ts.plusSeconds(30)),
                State.RETRY_PENDING, Reason.DEVICE_FAULT, BindingResult.Reason.CAPTURE_OUTSIDE_WINDOW);
    }

    // ------------------------------------------------------------------ F7 clock / format
    @Test
    void timestampFormatsWithMillisAndOffsetsBindWhenInstantMatches() throws Exception {
        for (String pattern : new String[] {"yyyy-MM-dd'T'HH:mm:ss.SSSXXX", "yyyy-MM-dd'T'HH:mm:ssXXX"}) {
            for (ZoneOffset off : new ZoneOffset[] {ZoneOffset.UTC, ZoneOffset.ofHoursMinutes(5, 30), ZoneOffset.ofHours(-7)}) {
                SessionHarness h = harness(new AttemptLedger.InMemory());
                h.session.start();
                h.untilReady();
                LivenessSession.CaptureRequest req = h.session.beginCapture();
                h.frames(10, Kind.LIVE);
                String ts = OffsetDateTime.ofInstant(Instant.ofEpochMilli(h.clock.wall - 200), off)
                        .format(DateTimeFormatter.ofPattern(pattern));
                byte[] resp = CaptureBinderTest.responseWithRawTimestamp(req.transactionId, ts);
                expect(h.session.onCaptureResponse(req.transactionId, resp), State.VERIFIED, Reason.OK, BindingResult.Reason.OK);
            }
        }
    }

    @Test
    void unparseableOrEpochTimestampIsMalformedAndFailsClosed() throws Exception {
        for (String ts : new String[] {"yesterday", "", "1793000000000", "2026-13-45T99:00:00Z"}) {
            SessionHarness h = harness(new AttemptLedger.InMemory());
            h.session.start();
            h.untilReady();
            LivenessSession.CaptureRequest req = h.session.beginCapture();
            h.frames(10, Kind.LIVE);
            SessionOutcome o = h.session.onCaptureResponse(req.transactionId,
                    CaptureBinderTest.responseWithRawTimestamp(req.transactionId, ts));
            expect(o, State.RETRY_PENDING, Reason.DEVICE_FAULT, BindingResult.Reason.MALFORMED_CONTENT);
            assertEquals(0, o.attackEvents);
        }
    }

    @Test
    void deviceClockSkewBeyondTheWindowToleranceFailsClosed() throws Exception {
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.ts = c.ts.plusSeconds(8)),
                State.RETRY_PENDING, Reason.DEVICE_FAULT, BindingResult.Reason.CAPTURE_OUTSIDE_WINDOW);
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.ts = c.ts.plusSeconds(3)),
                State.VERIFIED, Reason.OK, BindingResult.Reason.OK);
    }

    /** D1 (adversarial review): a transient wall step during beginCapture must not turn a genuine capture into an attack. */
    @Test
    void transientWallStepAtBeginCaptureDoesNotCreateAFalseAttackEvent() throws Exception {
        SessionHarness h = harness(new AttemptLedger.InMemory());
        h.session.start();
        h.untilReady();
        h.clock.wall -= 600_000;
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.clock.wall += 600_000;
        h.frames(10, Kind.LIVE);
        long deviceNow = h.clock.wall;
        byte[] resp = CaptureBinderTest.response(c -> { c.txn = req.transactionId; c.ts = Instant.ofEpochMilli(deviceNow - 200); });
        SessionOutcome o = h.session.onCaptureResponse(req.transactionId, resp);
        expect(o, State.VERIFIED, Reason.OK, BindingResult.Reason.OK);
        assertEquals(0, o.attackEvents);
    }

    // ------------------------------------------------------------------ F6 device trust
    @Test
    void expiredDeviceCertificateIsUntrusted() throws Exception {
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.dataChain = new X509Certificate[] {expiredCert, CaptureBinderTest.caCert}),
                State.REJECTED_ATTACK, Reason.CHANNEL_INTEGRITY, BindingResult.Reason.UNTRUSTED_DEVICE);
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.idChain = new X509Certificate[] {expiredCert, CaptureBinderTest.caCert}),
                State.REJECTED_ATTACK, Reason.CHANNEL_INTEGRITY, BindingResult.Reason.DIGITAL_ID_INVALID);
    }

    @Test
    void rogueSignerAndOtherDeviceAreIntegrityFailures() throws Exception {
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> {
                    c.dataKey = CaptureBinderTest.rogueKey;
                    c.dataChain = new X509Certificate[] {CaptureBinderTest.rogueCert};
                }), State.REJECTED_ATTACK, Reason.CHANNEL_INTEGRITY, BindingResult.Reason.UNTRUSTED_DEVICE);
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.serial = "OTHER-DEVICE"),
                State.REJECTED_ATTACK, Reason.BINDING_INTEGRITY, BindingResult.Reason.DEVICE_MISMATCH);
        expect(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.tamper = true),
                State.REJECTED_ATTACK, Reason.CHANNEL_INTEGRITY, BindingResult.Reason.BAD_SIGNATURE);
    }

    @Test
    void repeatedIntegrityFailuresLockTheSubjectOut() throws Exception {
        AttemptLedger ledger = new AttemptLedger.InMemory();
        SessionHarness h = harness(ledger);
        attempt(h, (c, r) -> c.serial = "OTHER-DEVICE");
        attempt(h, (c, r) -> c.serial = "OTHER-DEVICE");
        expect(h.session.retry(), State.FAILED_MAX_RETRIES, Reason.ATTACK_LIMIT, BindingResult.Reason.DEVICE_MISMATCH);
    }

    // ------------------------------------------------------------------ F5 morph (stub level)
    @Test
    void captureSubjectNotMatchingStreamIsRejectedBeforeVerification() throws Exception {
        // A morph/swap presented only to the capture: its embedding does not match the stream subject.
        // Stub-level: no morph images are generated or used; real morph detection is out of scope (plan F5).
        CaptureBinder morph = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
                CaptureBinderTest.stub(1, 0.95f, SessionHarness.OTHER), new CaptureBinder.Policy());
        SessionHarness h = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), morph, "L0");
        expect(attempt(h, (c, r) -> { }), State.REJECTED_ATTACK, Reason.BINDING_INTEGRITY, BindingResult.Reason.SUBJECT_MISMATCH);
    }

    @Test
    void capturePadBelowConservativeGateIsUncertainNotVerified() throws Exception {
        CaptureBinder low = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
                CaptureBinderTest.stub(1, 0.6f, SessionHarness.SUBJECT), new CaptureBinder.Policy());
        SessionHarness h = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), low, "L0");
        expect(attempt(h, (c, r) -> { }), State.RETRY_PENDING, Reason.CAPTURE_UNCERTAIN, BindingResult.Reason.PAD_UNCERTAIN);
        CaptureBinder atk = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
                CaptureBinderTest.stub(1, 0.1f, SessionHarness.SUBJECT), new CaptureBinder.Policy());
        h = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), atk, "L0");
        expect(attempt(h, (c, r) -> { }), State.REJECTED_ATTACK, Reason.CAPTURE_PAD_ATTACK, BindingResult.Reason.PAD_ATTACK);
    }
}
