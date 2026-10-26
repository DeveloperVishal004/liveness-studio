package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.session.SessionHarness.Kind;
import io.mosip.liveness.session.SessionOutcome.State;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Randomised event sequences (seeded, reproducible) against the decision engine. Checked after every event:
 * <ol>
 *   <li>VERIFIED only immediately after the verifier returned BOUND/OK for the in-flight request;</li>
 *   <li>a capture hash is reported iff the state is VERIFIED;</li>
 *   <li>terminal states never change;</li>
 *   <li>attempts never exceed the policy limit;</li>
 *   <li>no exception escapes the engine, whatever the order of events;</li>
 *   <li>I1: an attempt that saw an attack event never ends VERIFIED (only a new attempt can).</li>
 * </ol>
 */
class LivenessSessionInvariantTest {

    @Test
    void randomEventSequencesNeverViolateInvariants() {
        int verified = 0;
        for (int seed = 0; seed < 400; seed++) {
            verified += run(seed);
        }
        assertTrue(verified > 0, "the generator must also reach the positive path");
    }

    private int run(int seed) {
        Random r = new Random(seed);
        SessionHarness.StubVerifier v = new SessionHarness.StubVerifier();
        SessionHarness h = new SessionHarness(new SessionPolicy(), new AttemptLedger.InMemory(), v, null);
        h.session.start();
        LivenessSession.CaptureRequest req = null;
        State terminal = null;
        boolean lastBindWasBoundOk = false;
        int attackAttempt = 0;
        Outcome[] outs = Outcome.values();
        BindingResult.Reason[] reasons = BindingResult.Reason.values();
        for (int step = 0; step < 300; step++) {
            int seen = v.seen.size();
            int op = r.nextInt(100);
            try {
                if (op < 55) {
                    h.pad = r.nextInt(20) == 0 ? 0.1f : (r.nextInt(6) == 0 ? 0.6f : 0.95f);
                    h.embedding = r.nextInt(15) == 0 ? SessionHarness.OTHER : SessionHarness.SUBJECT;
                    h.embed = r.nextInt(8) != 0;
                    Kind k = r.nextInt(25) == 0 ? Kind.FROZEN : r.nextInt(25) == 0 ? Kind.STATIC
                            : r.nextInt(30) == 0 ? Kind.MULTI : Kind.LIVE;
                    h.frames(1 + r.nextInt(4), k);
                } else if (op < 65) {
                    if (h.session.state() == State.READY_FOR_CAPTURE) {
                        req = h.session.beginCapture();
                    }
                } else if (op < 78) {
                    if (req != null) {
                        Outcome o = r.nextInt(2) == 0 ? Outcome.BOUND : outs[r.nextInt(outs.length)];
                        BindingResult.Reason why = o == Outcome.BOUND ? BindingResult.Reason.OK : reasons[r.nextInt(reasons.length)];
                        float[] emb = r.nextInt(10) == 0 ? null : (r.nextInt(10) == 0 ? SessionHarness.OTHER : SessionHarness.SUBJECT);
                        v.next = BindingResult.of(o, why, r.nextInt(10) == 0 ? null : SessionHarness.HASH, emb);
                        v.toThrow = r.nextInt(40) == 0 ? new IllegalStateException() : null;
                        String txn = r.nextInt(6) == 0 ? "forged" : req.transactionId;
                        if (r.nextInt(30) == 0) {
                            h.clock.wall += (r.nextBoolean() ? 1 : -1) * 10_000;
                        }
                        h.session.onCaptureResponse(txn, new byte[0]);
                        lastBindWasBoundOk = v.seen.size() > seen && v.toThrow == null && o == Outcome.BOUND
                                && emb != null && v.next.signedDataSha256 != null;
                    }
                } else if (op < 86) {
                    h.clock.advance(r.nextInt(8_000));
                    h.session.tick();
                } else if (op < 93) {
                    h.session.retry();
                } else if (op < 95) {
                    h.session.onDeviceDisconnected("x");
                } else if (op < 97) {
                    h.session.recoverDevice();
                } else if (op < 98) {
                    h.session.cancel();
                } else if (op < 99) {
                    h.session.shutdown();
                } else {
                    h.session.onEngineError(new RuntimeException());
                }
            } catch (IllegalStateException e) {
                fail("seed " + seed + " step " + step + ": engine threw " + e);
            }
            SessionOutcome o = h.session.outcome();
            if (o.state == State.REJECTED_ATTACK) {
                attackAttempt = o.attempt;
            }
            if (o.state == State.VERIFIED) {
                assertTrue(o.attempt > attackAttempt, "I1 violated: VERIFIED in an attempt with an attack, seed " + seed);
            }
            if (terminal != null) {
                assertEquals(terminal, o.state, "terminal state changed, seed " + seed);
            } else if (o.state.terminal()) {
                terminal = o.state;
                if (o.state == State.VERIFIED) {
                    assertTrue(v.seen.size() == seen + 1 && lastBindWasBoundOk,
                            "VERIFIED without a fresh BOUND/OK binding, seed " + seed + " step " + step);
                }
            }
            if (o.state == State.VERIFIED) {
                assertNotNull(o.verifiedCaptureSha256);
            } else {
                assertNull(o.verifiedCaptureSha256);
            }
            assertTrue(o.attempt <= h.policy.maxAttempts);
        }
        return terminal == State.VERIFIED ? 1 : 0;
    }
}
