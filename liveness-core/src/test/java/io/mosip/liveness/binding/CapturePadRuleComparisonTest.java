package io.mosip.liveness.binding;

import io.mosip.liveness.binding.BindingResult.Outcome;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Old (conservative accept gate, default) vs proposed (veto-only, D4) capture-PAD rule on identical signed responses.
 *
 * <p>Properties checked over a grid of capture-PAD x subject:
 * <ol>
 *   <li>the proposed rule is never stricter than the old one (it only relaxes);</li>
 *   <li>the rules differ <em>only</em> where capture PAD is in [padAttack, 0.80) <em>and</em> the capture matches the stream
 *       subject - i.e. the relaxation never admits a different identity or a below-veto score;</li>
 *   <li>every cryptographic/freshness/device rejection is identical under both rules (rule-independent checks).</li>
 * </ol>
 * The printed table is reproduced in docs/phase0/SECURITY_ANALYSIS_CAPTURE_PAD_RULE.md.
 */
class CapturePadRuleComparisonTest {
    static final float[] PADS = {0.05f, 0.19f, 0.20f, 0.35f, 0.50f, 0.65f, 0.79f, 0.80f, 0.95f};

    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
    }

    private static BindingResult bind(CaptureBinder.Policy p, float pad, float[] emb) throws Exception {
        CaptureBinder b = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
                CaptureBinderTest.stub(1, pad, emb), p);
        return b.bind(CaptureBinderTest.response(c -> { }), CaptureBinderTest.ctx(5), Instant.now());
    }

    @Test
    void proposedRuleOnlyRelaxesSameSubjectMidScoreCaptures() throws Exception {
        List<String> table = new ArrayList<>();
        table.add(String.format("%-10s %-8s | %-28s | %-28s", "capturePAD", "subject", "OLD (accept gate 0.80)", "PROPOSED (veto-only)"));
        for (float pad : PADS) {
            for (String subj : new String[] {"same", "other"}) {
                float[] emb = subj.equals("same") ? CaptureBinderTest.SUBJECT : CaptureBinderTest.OTHER;
                BindingResult o = bind(CaptureBinder.Policy.conservativeAcceptGate(), pad, emb);
                BindingResult n = bind(CaptureBinder.Policy.proposedVetoOnly(), pad, emb);
                table.add(String.format("%-10.2f %-8s | %-28s | %-28s%s", pad, subj, o.outcome + "/" + o.reason,
                        n.outcome + "/" + n.reason, o.outcome == n.outcome ? "" : "   <-- differs"));
                boolean differs = o.outcome != n.outcome;
                boolean inRelaxedRegion = subj.equals("same") && pad >= 0.20f && pad < 0.80f;
                assertEquals(inRelaxedRegion, differs, "rules may differ only for same-subject captures with PAD in [0.20,0.80): pad="
                        + pad + " subj=" + subj);
                if (differs) {
                    assertEquals(Outcome.UNCERTAIN, o.outcome);
                    assertEquals(Outcome.BOUND, n.outcome);
                }
                // never stricter: anything the old rule binds, the new rule binds
                if (o.outcome == Outcome.BOUND) {
                    assertEquals(Outcome.BOUND, n.outcome);
                }
            }
        }
        System.out.println("CAPTURE-PAD RULE COMPARISON (stub analyzer; real signatures)\n" + String.join("\n", table));
    }

    @Test
    void ruleIndependentRejectionsAreIdentical() throws Exception {
        String[] names = {"tamper", "txn", "stale", "otherDevice"};
        for (String name : names) {
            BindingResult[] r = new BindingResult[2];
            CaptureBinder.Policy[] ps = {CaptureBinder.Policy.conservativeAcceptGate(), CaptureBinder.Policy.proposedVetoOnly()};
            for (int i = 0; i < 2; i++) {
                CaptureBinder b = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
                        CaptureBinderTest.stub(1, 0.5f, CaptureBinderTest.SUBJECT), ps[i]);
                byte[] resp = CaptureBinderTest.response(c -> {
                    switch (name) {
                        case "tamper": c.tamper = true; break;
                        case "txn": c.txn = "other"; break;
                        case "stale": c.ts = Instant.now().minusSeconds(3600); break;
                        default: c.serial = "OTHER";
                    }
                });
                r[i] = b.bind(resp, CaptureBinderTest.ctx(5), Instant.now());
            }
            assertEquals(r[0].outcome + "/" + r[0].reason, r[1].outcome + "/" + r[1].reason, name);
            assertTrue(r[0].outcome == Outcome.REJECTED, name);
        }
    }
}
