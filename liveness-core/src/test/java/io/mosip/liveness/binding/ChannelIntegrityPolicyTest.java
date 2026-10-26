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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Owner decision 2026-10-24: unattributable security failures count against the CHANNEL (persistent, locked over
 * maxChannelEvents, administrative reset only); attributable attacks keep the SUBJECT policy; nothing is ever accepted.
 * Real CaptureBinder + TEST-ONLY RS256 keys through LivenessSession. [CODE]
 */
class ChannelIntegrityPolicyTest {
    static final byte[] KEY = "channel-policy-test-key-0123456789abcd".getBytes(StandardCharsets.US_ASCII);
    static final String CHANNEL = "device:" + CaptureBinderTest.SERIAL;

    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
    }

    @TempDir
    Path dir;

    static CaptureBinder binder(float pad, float[] emb) {
        return new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier, CaptureBinderTest.stub(1, pad, emb),
                new CaptureBinder.Policy());
    }

    static SessionHarness harness(AttemptLedger l) {
        return new SessionHarness(new SessionPolicy(), l, binder(0.95f, SessionHarness.SUBJECT), "L0");
    }

    static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static void channelEvent(SessionOutcome o, int expectedChannelEvents) {
        assertEquals(State.REJECTED_ATTACK + "/" + Reason.CHANNEL_INTEGRITY, o.state + "/" + o.reason, o.toString());
        assertEquals(0, o.attackEvents, "never a subject attack event");
        assertEquals(expectedChannelEvents, o.channelEvents);
        assertNull(o.verifiedCaptureSha256);
    }

    // ------------------------------------------------------------------ every invalid response is rejected
    @Test
    void unattributableInvalidResponsesAreRejectedAsChannelEvents() throws Exception {
        String[] bodies = {"not json", "{}", "{\"biometrics\":[]}",
            "{\"biometrics\":[{\"data\":\"two.segments\",\"hash\":\"x\",\"error\":{\"errorCode\":\"0\"}}]}"};
        for (String body : bodies) {
            channelEvent(DeviceFaultPolicyTest.rawAttempt(harness(new AttemptLedger.InMemory()), b(body)), 1);
        }
        channelEvent(SessionBindingIntegrationTest.attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.tamper = true), 1);
        channelEvent(SessionBindingIntegrationTest.attempt(harness(new AttemptLedger.InMemory()), (c, r) -> {
            c.dataKey = CaptureBinderTest.rogueKey;
            c.dataChain = new X509Certificate[] {CaptureBinderTest.rogueCert};
        }), 1);
        channelEvent(SessionBindingIntegrationTest.attempt(harness(new AttemptLedger.InMemory()), (c, r) -> {
            c.idKey = CaptureBinderTest.rogueKey;
            c.idChain = new X509Certificate[] {CaptureBinderTest.rogueCert};
        }), 1);
        channelEvent(SessionBindingIntegrationTest.attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.txn = "other-request"), 1);
    }

    @Test
    void replayIsAChannelEventWithDiagnostics() throws Exception {
        AttemptLedger l = new AttemptLedger.InMemory();
        CaptureBinder shared = binder(0.95f, SessionHarness.SUBJECT);             // the replay cache lives in the binder
        SessionHarness h = new SessionHarness(new SessionPolicy(), l, shared, "L0");
        h.session.start();
        h.untilReady();
        LivenessSession.CaptureRequest req = h.session.beginCapture();
        h.frames(10, Kind.LIVE);
        long wall = h.clock.wall;
        byte[] captured = CaptureBinderTest.response(c -> { c.txn = req.transactionId; c.ts = java.time.Instant.ofEpochMilli(wall - 200); });
        assertEquals(State.VERIFIED, h.session.onCaptureResponse(req.transactionId, captured).state);
        SessionOutcome o = DeviceFaultPolicyTest.rawAttempt(new SessionHarness(new SessionPolicy(), l, shared, "L0"), captured);
        channelEvent(o, 1);
        assertEquals(BindingResult.Reason.REPLAYED_RESPONSE, o.bindingReason);
        assertTrue(l.lastChannelReason(CHANNEL).startsWith("REPLAYED_RESPONSE"), l.lastChannelReason(CHANNEL));
        assertTrue(o.detail.contains("REPLAYED_RESPONSE"), o.detail);
    }

    // ------------------------------------------------------------------ attributable attacks keep subject protection
    @Test
    void presentationAndEvidenceAttacksStillCountAgainstTheSubject() throws Exception {
        // capture PAD attack
        SessionHarness cap = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), binder(0.1f, SessionHarness.SUBJECT), "L0");
        SessionOutcome o1 = SessionBindingIntegrationTest.attempt(cap, (c, r) -> { });
        assertEquals(State.REJECTED_ATTACK + "/" + Reason.CAPTURE_PAD_ATTACK, o1.state + "/" + o1.reason);
        assertEquals(1, o1.attackEvents);
        // stream PAD attack
        SessionHarness st = harness(new AttemptLedger.InMemory());
        st.session.start();
        st.pad = 0.1f;
        st.frames(3, Kind.LIVE);
        assertEquals(1, st.session.outcome().attackEvents);
        assertEquals(Reason.STREAM_PAD_ATTACK, st.session.outcome().reason);
        // subject change during the attempt
        SessionHarness sc = harness(new AttemptLedger.InMemory());
        sc.embedding = SessionHarness.OTHER;
        sc.session.start();
        sc.untilReady();
        LivenessSession.CaptureRequest req = sc.session.beginCapture();
        sc.embedding = SessionHarness.SUBJECT;
        sc.frames(10, Kind.LIVE);
        long wall = sc.clock.wall;
        SessionOutcome o3 = sc.session.onCaptureResponse(req.transactionId,
                CaptureBinderTest.response(c -> { c.txn = req.transactionId; c.ts = java.time.Instant.ofEpochMilli(wall - 200); }));
        assertEquals(Reason.SUBJECT_CHANGED, o3.reason);
        assertEquals(1, o3.attackEvents);
        // device mismatch and subject mismatch
        SessionOutcome o4 = SessionBindingIntegrationTest.attempt(harness(new AttemptLedger.InMemory()), (c, r) -> c.serial = "OTHER-DEVICE");
        assertEquals(1, o4.attackEvents);
        assertEquals(0, o4.channelEvents);
        SessionHarness sm = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), binder(0.95f, SessionHarness.OTHER), "L0");
        assertEquals(1, SessionBindingIntegrationTest.attempt(sm, (c, r) -> { }).attackEvents);
        // the subject lockout still applies to attributable attacks
        SessionOutcome second = SessionBindingIntegrationTest.attempt(cap, (c, r) -> { });
        assertEquals(2, second.attackEvents);
        assertEquals(State.FAILED_MAX_RETRIES + "/" + Reason.ATTACK_LIMIT, cap.session.retry().state + "/" + cap.session.outcome().reason);
    }

    @Test
    void windowPadAttackStillCountsAgainstTheSubject() throws Exception {
        SessionHarness h = harness(new AttemptLedger.InMemory());
        SessionOutcome o = SessionBindingIntegrationTest.attempt(h, (c, r) -> { }, x -> {
            x.frames(3, Kind.LIVE);
            x.pad = 0.1f;
            x.frames(1, Kind.LIVE);
            x.pad = 0.95f;
        });
        assertEquals(Reason.WINDOW_PAD_ATTACK, o.reason, o.toString());
        assertEquals(1, o.attackEvents);
    }

    // ------------------------------------------------------------------ repeated channel attacks: flagged, fail closed
    @Test
    void repeatedChannelEventsLockTheChannelFailClosedWithoutConsumingFurtherAttempts() {
        AttemptLedger l = new AttemptLedger.InMemory();
        SessionHarness h = harness(l);
        channelEvent(DeviceFaultPolicyTest.rawAttempt(h, b("garbage-1")), 1);
        SessionOutcome locked = DeviceFaultPolicyTest.rawAttempt(h, b("garbage-2"));
        assertEquals(State.FAILED_POLICY + "/" + Reason.CHANNEL_INTEGRITY_LOCKED, locked.state + "/" + locked.reason, locked.toString());
        assertTrue(locked.channelLocked);
        assertEquals(0, locked.attackEvents);
        int attemptsUsed = l.attempts("subject-1");
        // any new session on this channel is refused at start, BEFORE an attempt is consumed
        SessionOutcome again = harness(l).session.start();
        assertEquals(State.FAILED_POLICY + "/" + Reason.CHANNEL_INTEGRITY_LOCKED, again.state + "/" + again.reason);
        assertTrue(again.detail.contains("administrative reset"), again.detail);
        assertEquals(attemptsUsed, l.attempts("subject-1"), "a locked channel consumes no further attempts");
    }

    // ------------------------------------------------------------------ the core property and recovery
    @Test
    void aMalformedResponseAttackerCannotPoisonTheSubjectAttackCounterAndGenuineUsersRecover() throws Exception {
        AttemptLedger l = new AttemptLedger.InMemory();
        SessionHarness h = harness(l);
        DeviceFaultPolicyTest.rawAttempt(h, b("garbage-1"));
        DeviceFaultPolicyTest.rawAttempt(h, b("garbage-2"));                       // channel locked
        assertEquals(0, l.attackEvents("subject-1"), "the attacker never touched the subject's attack counter");
        assertEquals(State.FAILED_POLICY, harness(l).session.start().state);
        l.resetChannel(CHANNEL, "supervisor-42", "loopback proxy removed; MDS reinstalled (ticket 1234)");
        SessionOutcome genuine = SessionBindingIntegrationTest.attempt(harness(l), (c, r) -> { });
        assertEquals(State.VERIFIED, genuine.state, "a genuine user recovers within the attempt budget: " + genuine);
        assertEquals(1, l.resetAudit().size());
        assertTrue(l.resetAudit().get(0).contains("supervisor-42"));
    }

    @Test
    void attemptBudgetStillAppliesToChannelEvents() {
        SessionPolicy p = new SessionPolicy();
        p.maxChannelEvents = 10;                                                    // channel lock out of the way
        SessionHarness h = new SessionHarness(p, new AttemptLedger.InMemory(), binder(0.95f, SessionHarness.SUBJECT), "L0");
        DeviceFaultPolicyTest.rawAttempt(h, b("g1"));
        DeviceFaultPolicyTest.rawAttempt(h, b("g2"));
        DeviceFaultPolicyTest.rawAttempt(h, b("g3"));
        assertEquals(State.FAILED_MAX_RETRIES + "/" + Reason.MAX_RETRIES, h.session.retry().state + "/" + h.session.outcome().reason,
                "no unlimited retry path");
    }

    // ------------------------------------------------------------------ persistence, restart, tamper, overflow
    @Test
    void channelCountsLockAndResetPersistAcrossRestarts() throws Exception {
        Path f = dir.resolve("ledger.dat");
        DeviceFaultPolicyTest.rawAttempt(harness(new FileAttemptLedger(f, KEY)), b("g1"));
        DeviceFaultPolicyTest.rawAttempt(harness(new FileAttemptLedger(f, KEY)), b("g2"));      // new session after restart
        FileAttemptLedger reloaded = new FileAttemptLedger(f, KEY);
        assertEquals(2, reloaded.channelEvents(CHANNEL));
        assertTrue(reloaded.lastChannelReason(CHANNEL).startsWith("MALFORMED_RESPONSE"));
        SessionOutcome lockedAfterRestart = harness(new FileAttemptLedger(f, KEY)).session.start();
        assertEquals(State.FAILED_POLICY + "/" + Reason.CHANNEL_INTEGRITY_LOCKED, lockedAfterRestart.state + "/" + lockedAfterRestart.reason);
        assertThrows(IllegalArgumentException.class, () -> reloaded.resetChannel(CHANNEL, " ", "x"), "authorization required");
        reloaded.resetChannel(CHANNEL, "supervisor-42", "investigated");
        FileAttemptLedger afterReset = new FileAttemptLedger(f, KEY);                          // restart again
        assertEquals(0, afterReset.channelEvents(CHANNEL));
        assertEquals(1, afterReset.resetAudit().size());
        assertTrue(afterReset.resetAudit().get(0).contains("previous=2") && afterReset.resetAudit().get(0).contains("supervisor-42"));
        assertEquals(State.CAPTURING, harness(afterReset).session.start().state);
    }

    @Test
    void tamperingWithChannelCountsMakesTheLedgerUntrusted() throws Exception {
        Path f = dir.resolve("ledger.dat");
        DeviceFaultPolicyTest.rawAttempt(harness(new FileAttemptLedger(f, KEY)), b("g1"));
        String text = new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
        String tampered = text.replaceFirst("\nc (\\S+) 1 ", "\nc $1 0 ");                    // erase the channel event
        assertTrue(!tampered.equals(text), "test precondition: the tamper must change the file");
        Files.write(f, tampered.getBytes(StandardCharsets.UTF_8));
        FileAttemptLedger t = new FileAttemptLedger(f, KEY);
        assertTrue(t.locked());
        SessionOutcome o = harness(t).session.start();
        assertEquals(State.FAILED_POLICY + "/" + Reason.LEDGER_UNTRUSTED, o.state + "/" + o.reason);
        assertThrows(IllegalStateException.class, () -> t.resetChannel(CHANNEL, "admin", "try to repair"),
                "a reset cannot launder a tampered ledger");
    }

    @Test
    void countersSaturateInsteadOfOverflowing() throws Exception {
        assertEquals(Integer.MAX_VALUE, AttemptLedger.inc(Integer.MAX_VALUE));
        assertEquals(1, AttemptLedger.inc(0));
        Path f = dir.resolve("ledger.dat");
        writeAuthentic(f, "c " + cid(CHANNEL) + " " + Integer.MAX_VALUE + " 0 -\n");
        FileAttemptLedger l = new FileAttemptLedger(f, KEY);
        assertTrue(!l.locked(), l.lockReason());
        assertEquals(Integer.MAX_VALUE, l.recordChannelEvent(CHANNEL, "x"));
        assertEquals(Integer.MAX_VALUE, new FileAttemptLedger(f, KEY).channelEvents(CHANNEL));
        writeAuthentic(f, "c " + cid(CHANNEL) + " " + (Integer.MAX_VALUE + 1L) + " 0 -\n");     // out of range
        assertTrue(new FileAttemptLedger(f, KEY).locked());
        writeAuthentic(f, "c " + cid(CHANNEL) + " -1 0 -\n");                                     // negative
        assertTrue(new FileAttemptLedger(f, KEY).locked());
    }

    // test helpers mirroring the ledger format (authenticated with the TEST key)
    static String cid(String channel) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(("channel:" + channel).getBytes(StandardCharsets.UTF_8)));
    }

    static byte[] hmac(byte[] d) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(KEY, "HmacSHA256"));
        return m.doFinal(d);
    }

    static void writeAuthentic(Path f, String lines) throws Exception {
        byte[] body = ("phase0-attempt-ledger/1\n" + lines).getBytes(StandardCharsets.UTF_8);
        Files.write(f, (new String(body, StandardCharsets.UTF_8) + "mac " + Base64.getEncoder().encodeToString(hmac(body)) + "\n")
                .getBytes(StandardCharsets.UTF_8));
    }
}
