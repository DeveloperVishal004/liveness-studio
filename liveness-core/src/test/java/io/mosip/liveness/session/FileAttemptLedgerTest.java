package io.mosip.liveness.session;

import io.mosip.liveness.session.SessionOutcome.Reason;
import io.mosip.liveness.session.SessionOutcome.State;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Persistence, restart, crash, tamper and concurrency behaviour of {@link FileAttemptLedger}. [CODE] */
class FileAttemptLedgerTest {
    static final byte[] KEY = "0123456789abcdef0123456789abcdef-test-only".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    Path file() {
        return dir.resolve("ledger.dat");
    }

    @Test
    void countsSurviveARestart() {
        FileAttemptLedger a = new FileAttemptLedger(file(), KEY);
        a.recordAttempt("reg-123");
        a.recordAttempt("reg-123");
        a.recordAttackEvent("reg-123");
        FileAttemptLedger b = new FileAttemptLedger(file(), KEY);     // "restart"
        assertEquals(2, b.attempts("reg-123"));
        assertEquals(1, b.attackEvents("reg-123"));
        assertEquals(0, b.attempts("reg-456"));
        assertFalse(b.locked());
    }

    @Test
    void restartCannotResetSessionLimits() {
        SessionPolicy p = new SessionPolicy();
        SessionHarness h1 = new SessionHarness(p, new FileAttemptLedger(file(), KEY), new SessionHarness.StubVerifier(), null);
        h1.session.start();
        for (int i = 0; i < 2; i++) {
            h1.clock.advance(11_000);
            h1.session.tick();
            h1.session.retry();
        }
        assertEquals(3, h1.session.outcome().attempt);
        // process restart: new ledger object from the same file, new session for the same subject
        SessionHarness h2 = new SessionHarness(p, new FileAttemptLedger(file(), KEY), new SessionHarness.StubVerifier(), null);
        SessionOutcome o = h2.session.start();
        assertEquals(State.FAILED_MAX_RETRIES + "/" + Reason.MAX_RETRIES, o.state + "/" + o.reason);
    }

    @Test
    void leftoverTempFileFromACrashIsIgnored() throws Exception {
        new FileAttemptLedger(file(), KEY).recordAttempt("reg-1");
        Files.write(dir.resolve("ledger.dat.tmp"), "half-written garbage".getBytes(StandardCharsets.US_ASCII));
        FileAttemptLedger b = new FileAttemptLedger(file(), KEY);
        assertEquals(1, b.attempts("reg-1"));
        b.recordAttempt("reg-1");                                       // overwrites the stale temp file
        assertEquals(2, new FileAttemptLedger(file(), KEY).attempts("reg-1"));
    }

    @Test
    void tamperingOrWrongKeyLocksTheLedgerFailClosed() throws Exception {
        new FileAttemptLedger(file(), KEY).recordAttempt("reg-1");
        String text = new String(Files.readAllBytes(file()), StandardCharsets.UTF_8);
        String tampered = text.replace(" 1 0 0\n", " 0 0 0\n");                        // reset the attempt count
        assertTrue(!tampered.equals(text), "test precondition: the tamper must change the file");
        Files.write(file(), tampered.getBytes(StandardCharsets.UTF_8));
        FileAttemptLedger t = new FileAttemptLedger(file(), KEY);
        assertTrue(t.locked(), "edited counts must be detected");
        assertEquals(Integer.MAX_VALUE, t.attempts("reg-1"));
        assertEquals(Integer.MAX_VALUE, t.attempts("any-other-subject"));
        SessionHarness h = new SessionHarness(new SessionPolicy(), t, new SessionHarness.StubVerifier(), null);
        SessionOutcome started = h.session.start();
        assertEquals(State.FAILED_POLICY + "/" + Reason.LEDGER_UNTRUSTED, started.state + "/" + started.reason);

        Files.write(file(), text.getBytes(StandardCharsets.UTF_8));
        byte[] other = "another-key-another-key-another-key!".getBytes(StandardCharsets.US_ASCII);
        assertTrue(new FileAttemptLedger(file(), other).locked(), "a file authenticated under another key is rejected");

        Files.write(file(), text.substring(0, text.length() / 2).getBytes(StandardCharsets.UTF_8));   // truncated
        assertTrue(new FileAttemptLedger(file(), KEY).locked());
    }

    @Test
    void lockedLedgerNeverWritesAndNeverResets() throws Exception {
        Files.write(file(), "garbage".getBytes(StandardCharsets.US_ASCII));
        FileAttemptLedger t = new FileAttemptLedger(file(), KEY);
        assertTrue(t.locked());
        t.recordAttempt("reg-1");
        assertEquals("garbage", new String(Files.readAllBytes(file()), StandardCharsets.US_ASCII));
    }

    @Test
    void subjectKeysAreNotStoredInPlaintext() throws Exception {
        new FileAttemptLedger(file(), KEY).recordAttempt("REG-2026-0001-NATIONAL-ID-777");
        String text = new String(Files.readAllBytes(file()), StandardCharsets.UTF_8);
        assertFalse(text.contains("REG-2026") || text.contains("777"), text);
    }

    @Test
    void persistenceFailureFailsClosedAndKeepsMemoryConsistent() throws Exception {
        FileAttemptLedger a = new FileAttemptLedger(file(), KEY);
        a.recordAttempt("reg-1");
        Files.createDirectory(dir.resolve("ledger.dat.tmp"));         // temp path unusable: write must fail
        assertThrows(IllegalStateException.class, () -> a.recordAttempt("reg-1"));
        assertEquals(1, a.attempts("reg-1"), "an attempt that was not persisted is not counted in memory either");
    }

    @Test
    void concurrentIncrementsAreAllPersisted() throws Exception {
        FileAttemptLedger a = new FileAttemptLedger(file(), KEY);
        List<Thread> ts = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            Thread th = new Thread(() -> {
                for (int i = 0; i < 25; i++) {
                    a.recordAttempt("reg-x");
                }
            });
            ts.add(th);
            th.start();
        }
        for (Thread th : ts) {
            th.join();
        }
        assertEquals(200, new FileAttemptLedger(file(), KEY).attempts("reg-x"));
    }

    @Test
    void shortKeysAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> new FileAttemptLedger(file(), new byte[16]));
    }

    /** A ledger whose writes fail (disk full, permissions, locked database). */
    static final class FailingLedger implements AttemptLedger {
        final boolean failAttempts;

        FailingLedger(boolean failAttempts) {
            this.failAttempts = failAttempts;
        }

        public int attempts(String k) { return 0; }

        public int attackEvents(String k) { return 0; }

        public int recordAttempt(String k) {
            if (failAttempts) {
                throw new IllegalStateException("disk full");
            }
            return 1;
        }

        public int recordAttackEvent(String k) { throw new IllegalStateException("disk full"); }

        public int channelEvents(String c) { return 0; }

        public int recordChannelEvent(String c, String r) { throw new IllegalStateException("disk full"); }

        public String lastChannelReason(String c) { return null; }

        public void resetChannel(String c, String by, String why) { throw new IllegalStateException("disk full"); }

        public java.util.List<String> resetAudit() { return java.util.Collections.emptyList(); }
    }

    @Test
    void unrecordableAttemptIsNeverStarted() {
        SessionHarness h = new SessionHarness(new SessionPolicy(), new FailingLedger(true), new SessionHarness.StubVerifier(), null);
        SessionOutcome o = h.session.start();
        assertEquals(State.ERROR_ENGINE + "/" + Reason.ENGINE_ERROR, o.state + "/" + o.reason, o.toString());
        h.frames(30, SessionHarness.Kind.LIVE);
        assertEquals(State.ERROR_ENGINE, h.session.state());
    }

    @Test
    void unrecordableAttackEventEndsTheSession() {
        SessionHarness h = new SessionHarness(new SessionPolicy(), new FailingLedger(false), new SessionHarness.StubVerifier(), null);
        h.session.start();
        h.pad = 0.1f;
        h.frames(3, SessionHarness.Kind.LIVE);                         // stream attack -> attack event -> write fails
        SessionOutcome o = h.session.outcome();
        assertEquals(State.ERROR_ENGINE, o.state, o.toString());
        assertTrue(o.state.terminal());
    }
}
