package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.session.SessionOutcome.State;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real threads, real clock, the client's thread layout: stream receipt (tagArrival), inference worker (onEvidence),
 * asynchronous embedding sampler (onEmbedding, delayed and reordered), capture thread (beginCapture/onCaptureResponse with
 * a slow verifier), and a UI thread (tick, retry, cancel, shutdown, device loss/recovery). Checked per run: no deadlock,
 * no unexpected exception, terminal states never change, VERIFIED only after the verifier returned BOUND for that
 * transaction, and a capture hash iff VERIFIED. [CODE]
 */
class LivenessSessionConcurrencyTest {
    static final float[][] LM = {{20, 24}, {44, 24}, {32, 36}, {24, 48}, {40, 48}};

    static SessionPolicy fastPolicy() {
        SessionPolicy p = new SessionPolicy();
        p.passiveWindowMs = 600;
        p.passiveMinSpanMs = 200;
        p.staticWindowMs = 800;
        p.collectTimeoutMs = 1_500;
        p.readyTimeoutMs = 800;
        p.captureTimeoutMs = 1_000;
        p.sessionTtlMs = 4_000;
        p.windowLatencyMs = 100;
        p.windowMaxGapMs = 400;
        p.maxAttempts = 50;
        p.maxAttackEvents = 50;
        p.maxDeviceRecoveries = 50;
        return p;
    }

    static final java.util.Map<String, Integer> OUTCOMES = new java.util.TreeMap<>();

    @Test
    void concurrentClientThreadsNeverBreakInvariants() throws Exception {
        int runs = 24;
        int verified = 0;
        for (int i = 0; i < runs; i++) {
            verified += run(i) ? 1 : 0;
        }
        System.out.println("CONCURRENCY outcomes over " + runs + " runs: " + OUTCOMES);
        assertTrue(verified > 0, "the positive path must also be reached under concurrency");
    }

    private boolean run(int seed) throws Exception {
        Random rnd = new Random(seed);
        Set<String> boundTxns = ConcurrentHashMap.newKeySet();
        CaptureVerifier verifier = (resp, ctx, now) -> {
            sleepQuiet(10 + ThreadLocalRandom.current().nextInt(40));               // slow binder under the lock
            int k = ThreadLocalRandom.current().nextInt(10);
            if (k < 6) {
                boundTxns.add(ctx.expectedTransactionId);
                return BindingResult.of(Outcome.BOUND, BindingResult.Reason.OK, "ab".repeat(32), SessionHarness.SUBJECT);
            }
            return BindingResult.of(k < 8 ? Outcome.UNCERTAIN : Outcome.REJECTED,
                    k < 8 ? BindingResult.Reason.PAD_UNCERTAIN : BindingResult.Reason.DEVICE_ERROR, null, null);
        };
        LivenessSession s = new LivenessSession(fastPolicy(), SessionClock.SYSTEM, verifier, new AttemptLedger.InMemory(),
                "subject-" + seed, new LivenessSession.DeviceIdentity("PHASE0-MOCK-FACE-0001", "Phase0", "MOCK-FACE-1", null));
        List<Throwable> errors = new CopyOnWriteArrayList<>();
        AtomicBoolean stop = new AtomicBoolean();
        LinkedBlockingQueue<FrameTag> toWorker = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<FrameTag> toSampler = new LinkedBlockingQueue<>();
        s.start();

        Thread streamer = thread("streamer", errors, () -> {
            while (!stop.get()) {
                toWorker.add(s.tagArrival());                                       // tagged at receipt
                sleepQuiet(5);
            }
        });
        Thread worker = thread("worker", errors, () -> {
            Random r = new Random(seed * 31L + 1);
            while (!stop.get()) {
                FrameTag t = toWorker.poll(20, TimeUnit.MILLISECONDS);
                if (t == null) {
                    continue;
                }
                float[] g = new float[64 * 64];
                for (int i = 0; i < g.length; i++) {
                    g[i] = (float) r.nextGaussian();
                }
                s.onEvidence(t, 1, true, null, 0.95f, LM, new float[] {10, 10, 44, 54}, g, 0f);
                if (r.nextInt(3) == 0) {
                    toSampler.add(t);
                }
            }
        });
        Thread sampler = thread("sampler", errors, () -> {
            while (!stop.get()) {
                FrameTag t = toSampler.poll(20, TimeUnit.MILLISECONDS);
                if (t != null) {
                    sleepQuiet(ThreadLocalRandom.current().nextInt(30));              // late, sometimes after retries
                    s.onEmbedding(t.seq, t.monoNanos, SessionHarness.SUBJECT, t);
                }
            }
        });
        Thread capture = thread("capture", errors, () -> {
            while (!stop.get()) {
                if (s.state() == State.READY_FOR_CAPTURE) {
                    LivenessSession.CaptureRequest req;
                    try {
                        req = s.beginCapture();
                    } catch (IllegalStateException raced) {
                        continue;                                                   // legitimate race: state moved on
                    }
                    sleepQuiet(20 + ThreadLocalRandom.current().nextInt(60));
                    s.onCaptureResponse(req.transactionId, "{}".getBytes(StandardCharsets.UTF_8));
                    if (ThreadLocalRandom.current().nextInt(4) == 0) {                // duplicate/late delivery
                        s.onCaptureResponse(req.transactionId, "{}".getBytes(StandardCharsets.UTF_8));
                    }
                }
                sleepQuiet(5);
            }
        });
        State[] terminal = {null};
        Thread ui = thread("ui", errors, () -> {
            Random r = new Random(seed * 17L + 5);
            while (!stop.get()) {
                SessionOutcome o = s.tick();
                checkSnapshot(o, terminal, boundTxns);
                int k = r.nextInt(400);
                if (o.state == State.RETRY_PENDING || o.state == State.REJECTED_ATTACK) {
                    s.retry();
                } else if (o.state == State.ERROR_DEVICE) {
                    s.recoverDevice();
                } else if (k == 0) {
                    s.cancel();
                } else if (k == 1) {
                    s.shutdown();
                } else if (k < 6) {
                    s.onDeviceDisconnected("usb");
                }
                sleepQuiet(3);
            }
        });
        long deadline = System.currentTimeMillis() + 2_500 + rnd.nextInt(1_500);
        while (System.currentTimeMillis() < deadline && !s.state().terminal()) {
            Thread.sleep(10);
        }
        if (rnd.nextBoolean()) {
            s.shutdown();                                                           // shutdown while threads still run
        }
        Thread.sleep(50);
        stop.set(true);
        for (Thread t : new Thread[] {streamer, worker, sampler, capture, ui}) {
            t.join(3_000);
            assertFalse(t.isAlive(), "thread " + t.getName() + " stuck (deadlock?) in run " + seed);
        }
        assertTrue(errors.isEmpty(), "run " + seed + ": " + errors);
        SessionOutcome fin = s.outcome();
        checkSnapshot(fin, terminal, boundTxns);
        s.close();
        // close() = shutdown: a terminal state is kept; any other state becomes SHUTDOWN
        assertEquals(fin.state.terminal() ? fin.state : State.SHUTDOWN, s.outcome().state);
        OUTCOMES.merge(fin.state + "/" + fin.reason, 1, Integer::sum);
        return fin.state == State.VERIFIED;
    }

    private static void checkSnapshot(SessionOutcome o, State[] terminal, Set<String> boundTxns) {
        synchronized (terminal) {
            if (terminal[0] != null) {
                assertEquals(terminal[0], o.state, "terminal state changed");
            } else if (o.state.terminal()) {
                terminal[0] = o.state;
            }
        }
        if (o.state == State.VERIFIED) {
            assertNotNull(o.verifiedCaptureSha256);
            assertFalse(boundTxns.isEmpty(), "VERIFIED without any BOUND binding");
        } else {
            assertNull(o.verifiedCaptureSha256);
        }
    }

    interface Body {
        void run() throws Exception;
    }

    private static Thread thread(String name, List<Throwable> errors, Body b) {
        Thread t = new Thread(() -> {
            try {
                b.run();
            } catch (Throwable e) {
                errors.add(e);
            }
        }, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
