package io.mosip.liveness.binding;

import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.FileAttemptLedger;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionHarness;
import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import io.mosip.liveness.session.SessionPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Owner decision 2026-10-24: non-conforming responses from the EXPECTED, authenticated device are device faults
 * (rejected, never evidence, no attack event, attempt cap applies); security failures keep the attack policy.
 * Real CaptureBinder + RS256 TEST-ONLY keys through LivenessSession. [CODE]
 */
class DeviceFaultPolicyTest {
    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
    }

    @TempDir
    Path dir;

    final CaptureBinder binder = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
            CaptureBinderTest.stub(1, 0.95f, SessionHarness.SUBJECT), new CaptureBinder.Policy());

    SessionHarness harness(AttemptLedger ledger) {
        return new SessionHarness(new SessionPolicy(), ledger, binder, "L0");
    }

    static SessionOutcome attempt(SessionHarness h, BiConsumer<CaptureBinderTest.Capture, LivenessSession.CaptureRequest> edit)
            throws Exception {
        return SessionBindingIntegrationTest.attempt(h, edit);
    }

    /** One attempt whose RCAPTURE response body is given verbatim (pre-authentication malformations). */
    static SessionOutcome rawAttempt(SessionHarness h, byte[] body) {
        if (h.session.state() == State.CREATED) {
            h.session.start();
        } else {
            h.session.retry();
        }
        assertEquals(State.READY_FOR_CAPTURE, h.untilReady());
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        return h.session.onCaptureResponse(req.transactionId, body);
    }

    static void deviceFault(SessionOutcome o, BindingResult.Reason why) {
        assertEquals(State.RETRY_PENDING + "/" + Reason.DEVICE_FAULT + "/" + why, o.state + "/" + o.reason + "/" + o.bindingReason, o.toString());
        assertEquals(0, o.attackEvents, "a device fault must not be an attack event");
        assertNull(o.verifiedCaptureSha256);
    }

    /** Unattributable security failure: rejected, counted against the channel, NOT a subject attack event. */
    static void channel(SessionOutcome o, BindingResult.Reason why) {
        assertEquals(State.REJECTED_ATTACK + "/" + Reason.CHANNEL_INTEGRITY + "/" + why, o.state + "/" + o.reason + "/" + o.bindingReason, o.toString());
        assertEquals(0, o.attackEvents, "unattributable: no subject attack event");
        assertEquals(1, o.channelEvents);
        assertNull(o.verifiedCaptureSha256);
    }

    static void security(SessionOutcome o, BindingResult.Reason why) {
        assertEquals(State.REJECTED_ATTACK + "/" + Reason.BINDING_INTEGRITY + "/" + why, o.state + "/" + o.reason + "/" + o.bindingReason, o.toString());
        assertEquals(1, o.attackEvents);
        assertNull(o.verifiedCaptureSha256);
    }

    // ------------------------------------------------------------------ device faults
    @Test
    void missingNonceFromTheExpectedDeviceIsADeviceFault() throws Exception {
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.omitTxn = true), BindingResult.Reason.TRANSACTION_ABSENT);
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.txn = null), BindingResult.Reason.TRANSACTION_ABSENT);
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.txn = "  "), BindingResult.Reason.TRANSACTION_ABSENT);
    }

    @Test
    void malformedContentOfAnAuthenticatedBoundResponseIsADeviceFault() throws Exception {
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.rawTimestamp = "not-a-time"), BindingResult.Reason.MALFORMED_CONTENT);
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.rawTimestamp = ""), BindingResult.Reason.MALFORMED_CONTENT);
    }

    @Test
    void deviceClockSkewIsADeviceFault() throws Exception {
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.ts = c.ts.plusSeconds(30)), BindingResult.Reason.CAPTURE_OUTSIDE_WINDOW);
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.ts = c.ts.minus(Duration.ofMinutes(15))), BindingResult.Reason.CAPTURE_STALE);
        deviceFault(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.ts = c.ts.plus(Duration.ofMinutes(15))), BindingResult.Reason.CAPTURE_FROM_FUTURE);
    }

    // ------------------------------------------------------------------ security failures are NOT reclassified
    @Test
    void transactionMismatchSignatureTrustReplayDeviceAndSubjectStaySecurityFailures() throws Exception {
        channel(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.txn = "another-request"), BindingResult.Reason.TRANSACTION_MISMATCH);
        channel(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.tamper = true), BindingResult.Reason.BAD_SIGNATURE);
        channel(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> {
            c.dataKey = CaptureBinderTest.rogueKey;
            c.dataChain = new X509Certificate[] {CaptureBinderTest.rogueCert};
        }), BindingResult.Reason.UNTRUSTED_DEVICE);
        security(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.serial = "OTHER-DEVICE"), BindingResult.Reason.DEVICE_MISMATCH);
        CaptureBinder other = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
                CaptureBinderTest.stub(1, 0.95f, SessionHarness.OTHER), new CaptureBinder.Policy());
        security(attempt(new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), other, "L0"), (c, r) -> { }),
                BindingResult.Reason.SUBJECT_MISMATCH);
    }

    @Test
    void aMissingNonceNeverMasksASecurityFailure() throws Exception {
        // the device checks run BEFORE nonce classification: absent nonce + another device / bad signature / untrusted key
        security(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> { c.omitTxn = true; c.serial = "OTHER-DEVICE"; }),
                BindingResult.Reason.DEVICE_MISMATCH);
        channel(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> { c.omitTxn = true; c.tamper = true; }),
                BindingResult.Reason.BAD_SIGNATURE);
        channel(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> {
            c.omitTxn = true;
            c.dataKey = CaptureBinderTest.rogueKey;
            c.dataChain = new X509Certificate[] {CaptureBinderTest.rogueCert};
        }), BindingResult.Reason.UNTRUSTED_DEVICE);
        security(attempt(harness(new AttemptLedger.InMemory()), (c, r) -> { c.omitTxn = true; c.ts = c.ts.plusSeconds(30); c.serial = "OTHER-DEVICE"; }),
                BindingResult.Reason.DEVICE_MISMATCH);
    }

    @Test
    void replayOfANonceLessResponseIsASecurityFailure() throws Exception {
        SessionHarness h = harness(new AttemptLedger.InMemory());
        byte[][] first = new byte[1][];
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        first[0] = CaptureBinderTest.response(c -> { c.omitTxn = true; c.ts = java.time.Instant.ofEpochMilli(h.clock.wall - 200); });
        deviceFault(h.session.onCaptureResponse(req.transactionId, first[0]), BindingResult.Reason.TRANSACTION_ABSENT);
        SessionOutcome o = rawAttempt(h, first[0]);                     // the same signed bytes again, next attempt
        assertEquals(State.REJECTED_ATTACK + "/" + BindingResult.Reason.REPLAYED_RESPONSE, o.state + "/" + o.bindingReason, o.toString());
        assertEquals(Reason.CHANNEL_INTEGRITY, o.reason);
        assertEquals(0, o.attackEvents);
    }

    @Test
    void preAuthenticationMalformedResponsesStayUnattributableSecurityFailures() throws Exception {
        channel(rawAttempt(harness(new AttemptLedger.InMemory()), "not json".getBytes(StandardCharsets.UTF_8)),
                BindingResult.Reason.MALFORMED_RESPONSE);
        channel(rawAttempt(harness(new AttemptLedger.InMemory()), "{\"biometrics\":[]}".getBytes(StandardCharsets.UTF_8)),
                BindingResult.Reason.MALFORMED_RESPONSE);
        channel(rawAttempt(harness(new AttemptLedger.InMemory()),
                "{\"biometrics\":[{\"specVersion\":\"0.9.5\",\"data\":\"garbage\",\"hash\":\"x\",\"error\":{\"errorCode\":\"0\"}}]}"
                        .getBytes(StandardCharsets.UTF_8)), BindingResult.Reason.MALFORMED_RESPONSE);
    }

    // ------------------------------------------------------------------ attempt cap, diagnosis flag, persistence
    @Test
    void repeatedDeviceFaultsAreFlaggedAndExhaustAttemptsWithoutAttackLockout() throws Exception {
        SessionHarness h = harness(new AttemptLedger.InMemory());
        SessionOutcome o1 = attempt(h, (c, r) -> c.omitTxn = true);
        deviceFault(o1, BindingResult.Reason.TRANSACTION_ABSENT);
        assertFalse(o1.deviceFaultFlag);
        SessionOutcome o2 = attempt(h, (c, r) -> c.ts = c.ts.plusSeconds(30));
        deviceFault(o2, BindingResult.Reason.CAPTURE_OUTSIDE_WINDOW);
        assertTrue(o2.deviceFaultFlag, "two device faults flag the device for diagnosis");
        SessionOutcome o3 = attempt(h, (c, r) -> c.rawTimestamp = "bad");
        deviceFault(o3, BindingResult.Reason.MALFORMED_CONTENT);
        assertEquals(3, o3.attempt);
        SessionOutcome end = h.session.retry();
        assertEquals(State.FAILED_MAX_RETRIES + "/" + Reason.MAX_RETRIES, end.state + "/" + end.reason, "cap applies; not ATTACK_LIMIT");
        assertEquals(0, end.attackEvents);
        assertEquals(3, end.deviceFaults);
    }

    @Test
    void deviceFaultsPersistAcrossRestartsAndNeverBecomeAttackEvents() throws Exception {
        byte[] key = "persistent-ledger-test-key-0123456789".getBytes(StandardCharsets.US_ASCII);
        Path f = dir.resolve("ledger.dat");
        SessionHarness a = harness(new FileAttemptLedger(f, key));
        deviceFault(attempt(a, (c, r) -> c.omitTxn = true), BindingResult.Reason.TRANSACTION_ABSENT);
        deviceFault(attempt(a, (c, r) -> c.omitTxn = true), BindingResult.Reason.TRANSACTION_ABSENT);
        // process restart: new ledger object from the same file, new session for the same subject
        FileAttemptLedger reloaded = new FileAttemptLedger(f, key);
        assertEquals(2, reloaded.attempts("subject-1"));
        assertEquals(0, reloaded.attackEvents("subject-1"));
        assertEquals(2, reloaded.deviceFaults("subject-1"));
        SessionHarness b = harness(reloaded);
        SessionOutcome o = attempt(b, (c, r) -> { });                    // third and last attempt: a valid capture
        assertEquals(State.VERIFIED, o.state, "a fresh valid attempt within the cap still verifies: " + o);
        assertTrue(o.deviceFaultFlag, "persisted faults keep the diagnosis flag after restart");
        SessionHarness c = harness(new FileAttemptLedger(f, key));
        assertEquals(State.FAILED_MAX_RETRIES, c.session.start().state, "cap persists across restarts");
    }

    @Test
    void mixedFaultsCountOnlyAttributableFailuresAsSubjectAttacks() throws Exception {
        SessionHarness h = harness(new AttemptLedger.InMemory());
        deviceFault(attempt(h, (c, r) -> c.omitTxn = true), BindingResult.Reason.TRANSACTION_ABSENT);
        SessionOutcome o = attempt(h, (c, r) -> c.txn = "another-request");          // channel event
        assertEquals(State.REJECTED_ATTACK, o.state);
        assertEquals(0, o.attackEvents);
        assertEquals(1, o.channelEvents);
        SessionOutcome d = attempt(h, (c, r) -> c.serial = "OTHER-DEVICE");          // attributable: subject attack
        assertEquals(1, d.attackEvents);
    }

    @Test
    void noFaultyOrInvalidResponseEverVerifies() throws Exception {
        java.util.List<BiConsumer<CaptureBinderTest.Capture, LivenessSession.CaptureRequest>> bad = java.util.Arrays.asList(
                (c, r) -> c.omitTxn = true, (c, r) -> c.txn = null, (c, r) -> c.rawTimestamp = "x",
                (c, r) -> c.ts = c.ts.plusSeconds(30), (c, r) -> c.ts = c.ts.minus(Duration.ofMinutes(15)),
                (c, r) -> c.txn = "other", (c, r) -> c.tamper = true, (c, r) -> c.serial = "OTHER",
                (c, r) -> { c.omitTxn = true; c.serial = "OTHER"; }, (c, r) -> c.errorCode = "701");
        for (BiConsumer<CaptureBinderTest.Capture, LivenessSession.CaptureRequest> e : bad) {
            SessionOutcome o = attempt(harness(new AttemptLedger.InMemory()), e);
            assertTrue(o.state != State.VERIFIED, o.toString());
            assertNull(o.verifiedCaptureSha256);
        }
    }
}
