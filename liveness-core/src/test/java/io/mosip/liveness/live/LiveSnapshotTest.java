package io.mosip.liveness.live;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The snapshot adds no evidence: stages and integrity checks are derived from what the engine actually did. These tests
 * pin the ordering rules and the invariant that nothing is "passed" that the engine did not pass. [CODE]
 */
class LiveSnapshotTest {
    static final LiveSnapshot.Thresholds T = new LiveSnapshot.Thresholds();
    static final ObjectMapper JSON = new ObjectMapper();

    static LiveTrialController.Status status(String state, String reason, String binding, boolean captureIssued) {
        LiveTrialController.Status s = new LiveTrialController.Status();
        s.trial = 1;
        s.trialId = "T1-test";
        s.state = state;
        s.reason = reason;
        s.bindingReason = binding;
        s.captureIssued = captureIssued;
        s.frames = 60;
        s.eligibleFrames = 55;
        s.faceCount = 1;
        s.eligible = true;
        s.medianPad = 0.97f;
        s.lastPad = 0.97f;
        s.verdict = "verdict text";
        s.startedAtMs = 1000;
        s.finishedAtMs = "CAPTURING".equals(state) ? 0 : 5000;
        s.trialActive = "CAPTURING".equals(state);
        return s;
    }

    static String[] states(List<Map<String, Object>> checks) {
        return checks.stream().map(c -> (String) c.get("state")).toArray(String[]::new);
    }

    @Test
    void idleShowsNothingPassed() {
        LiveTrialController.Status s = new LiveTrialController.Status();
        for (Map<String, Object> st : LiveSnapshot.stages(s, T)) {
            assertEquals("pending", st.get("state"), String.valueOf(st.get("id")));
        }
        for (Map<String, Object> c : LiveSnapshot.integrity(s)) {
            assertTrue("not_checked".equals(c.get("state")) || "not_applicable".equals(c.get("state")), c.toString());
        }
    }

    @Test
    void noCaptureMeansNoIntegrityCheckIsEverShownAsPassed() {
        LiveTrialController.Status s = status("RETRY_PENDING", "STATIC_REPLAY_SUSPECT", null, false);
        for (Map<String, Object> c : LiveSnapshot.integrity(s)) {
            assertFalse("passed".equals(c.get("state")), "a check that never ran must not pass: " + c);
        }
        Map<String, Object> temporal = LiveSnapshot.stages(s, T).get(3);
        assertEquals("temporal", temporal.get("id"));
        assertEquals("attention", temporal.get("state"));
        assertEquals("STATIC_REPLAY_SUSPECT", temporal.get("reasonCode"));
        assertEquals("skipped", LiveSnapshot.stages(s, T).get(4).get("state"));
    }

    @Test
    void checksFollowTheBinderOrderAndStopAtTheFirstFailure() {
        String p = "passed", f = "failed", n = "not_checked";
        Object[][] table = {
                {"MALFORMED_RESPONSE", new String[] {f, n, n, n, n, n, n, n, n, n}},
                {"BAD_SIGNATURE", new String[] {p, f, n, n, n, n, n, n, n, n}},
                {"UNTRUSTED_DEVICE", new String[] {p, p, f, n, n, n, n, n, n, n}},
                {"REPLAYED_RESPONSE", new String[] {p, p, p, f, n, n, n, n, n, n}},
                {"DEVICE_MISMATCH", new String[] {p, p, p, p, f, n, n, n, n, n}},
                {"TRANSACTION_MISMATCH", new String[] {p, p, p, p, p, f, n, n, n, n}},
                {"CAPTURE_OUTSIDE_WINDOW", new String[] {p, p, p, p, p, p, f, n, n, n}},
                {"BAD_BIO_FORMAT", new String[] {p, p, p, p, p, p, p, f, n, n}},
                {"NO_FACE", new String[] {p, p, p, p, p, p, p, p, f, n}},
                {"MULTIPLE_FACES", new String[] {p, p, p, p, p, p, p, p, f, n}},
                {"PAD_ATTACK", new String[] {p, p, p, p, p, p, p, p, p, n}},
                {"INSUFFICIENT_STREAM_EVIDENCE", new String[] {p, p, p, p, p, p, p, p, p, n}},
                {"SUBJECT_MISMATCH", new String[] {p, p, p, p, p, p, p, p, p, f}},
                {"PAD_UNCERTAIN", new String[] {p, p, p, p, p, p, p, p, p, p}},
        };
        for (Object[] row : table) {
            LiveTrialController.Status s = status("RETRY_PENDING", "BINDING_REJECTED", (String) row[0], true);
            String[] got = states(LiveSnapshot.integrity(s));
            for (int i = 0; i < 10; i++) {
                assertEquals(((String[]) row[1])[i], got[i], row[0] + " check " + LiveSnapshot.CHECK_IDS[i]);
            }
            assertEquals("not_applicable", got[10], "the unsigned-stream row is never passed or failed");
        }
    }

    @Test
    void aSuccessfulBindingPassesEverythingOnlyWhenTheSessionIsVerified() {
        LiveTrialController.Status v = status("VERIFIED", "OK", "OK", true);
        String[] vs = states(LiveSnapshot.integrity(v));
        for (int i = 0; i < 10; i++) {
            assertEquals("passed", vs[i], LiveSnapshot.CHECK_IDS[i]);
        }
        // bound by the binder but the session then refused (window problem): the whole-attempt subject check was not reached
        LiveTrialController.Status w = status("RETRY_PENDING", "STATIC_IN_WINDOW", "OK", true);
        assertEquals("not_checked", states(LiveSnapshot.integrity(w))[9]);
        // whole-attempt subject failure after a good binding
        LiveTrialController.Status c = status("REJECTED_ATTACK", "SUBJECT_CHANGED", "OK", true);
        assertEquals("failed", states(LiveSnapshot.integrity(c))[9]);
    }

    @Test
    void checksNeverPassAfterANonPassAndFailAtMostOnce() {
        String[] reasons = {"MALFORMED_RESPONSE", "DEVICE_ERROR", "BAD_SIGNATURE", "UNTRUSTED_DEVICE", "REPLAYED_RESPONSE",
                "DIGITAL_ID_INVALID", "DEVICE_MISMATCH", "TRANSACTION_ABSENT", "TRANSACTION_MISMATCH", "MALFORMED_CONTENT",
                "CAPTURE_STALE", "CAPTURE_FROM_FUTURE", "CAPTURE_OUTSIDE_WINDOW", "BAD_BIO_FORMAT", "NO_FACE", "MULTIPLE_FACES",
                "PAD_ATTACK", "INSUFFICIENT_STREAM_EVIDENCE", "SUBJECT_MISMATCH", "PAD_UNCERTAIN", "OK", "ENGINE_ERROR", "SOMETHING_NEW", ""};
        for (String r : reasons) {
            String[] st = states(LiveSnapshot.integrity(status("RETRY_PENDING", "BINDING_REJECTED", r, true)));
            boolean seenNonPass = false;
            int failed = 0;
            for (int i = 0; i < 10; i++) {
                if ("passed".equals(st[i])) {
                    assertFalse(seenNonPass, r + ": passed after a non-pass at " + i + " " + String.join(",", st));
                } else {
                    seenNonPass = true;
                }
                if ("failed".equals(st[i])) {
                    failed++;
                }
            }
            assertTrue(failed <= 1, r);
        }
    }

    @Test
    void aCaptureThatCouldNotRunMakesEveryCheckUnavailableNotFailedOrPassed() {
        LiveTrialController.Status s = status("CAPTURING", "NONE", null, true);
        s.detail = "RCAPTURE failed: java.io.IOException: device unplugged";
        for (String c : java.util.Arrays.copyOf(states(LiveSnapshot.integrity(s)), 10)) {
            assertEquals("unavailable", c);
        }
        assertEquals("failed", LiveSnapshot.stages(s, T).get(4).get("state"));
    }

    @Test
    void theDecisionStageIsPassedOnlyForAVerifiedEngineOutcomeWhateverElseIsTrue() {
        String[] states = {"CAPTURING", "READY_FOR_CAPTURE", "CAPTURE_IN_FLIGHT", "RETRY_PENDING", "REJECTED_ATTACK", "FAILED_POLICY",
                "FAILED_MAX_RETRIES", "ERROR_ENGINE", "ERROR_DEVICE", "EXPIRED", "CANCELLED", "VERIFIED", "IDLE", "WHATEVER"};
        for (String state : states) {
            LiveTrialController.Status s = status(state, "NONE", "OK", true);
            s.medianPad = 1.0f;
            s.capturePad = 1.0f;
            s.readyMs = 900L;
            s.faceCount = 1;
            s.eligible = true;
            Map<String, Object> decision = LiveSnapshot.stages(s, T).get(7);
            assertEquals("decision", decision.get("id"));
            assertEquals("VERIFIED".equals(state), "passed".equals(decision.get("state")),
                    state + ": a face, a perfect PAD score and a bound capture are not a verification by themselves");
        }
    }

    @Test
    void thresholdsComeFromThePolicyObjectNotFromTheViewLayer() {
        LiveSnapshot.Thresholds t = new LiveSnapshot.Thresholds();
        t.streamAccept = 0.90f;
        t.captureAccept = 0.95f;
        LiveTrialController.Status s = status("CAPTURING", "NONE", null, false);
        s.medianPad = 0.85f;
        assertEquals("attention", LiveSnapshot.stages(s, t).get(2).get("state"), "0.85 is below this policy's 0.90 accept line");
        assertEquals("passed", LiveSnapshot.stages(s, T).get(2).get("state"), "but above the default 0.80");
        assertTrue(String.valueOf(LiveSnapshot.stages(s, t).get(2).get("detail")).contains("0.90"));
        assertEquals(0.90f, ((Number) ((Map<?, ?>) LiveSnapshot.info(t, "cam").get("thresholds")).get("streamAccept")).floatValue(), 0f);
    }

    @Test
    void nonFiniteValuesNeverReachTheJson() throws Exception {
        LiveTrialController.Status s = status("CAPTURING", "NONE", null, false);
        s.frameProcessingMs = Double.NaN;
        s.frameAgeMs = Double.POSITIVE_INFINITY;
        s.medianPad = Float.NaN;
        s.lastPad = Float.POSITIVE_INFINITY;
        s.capturePad = Float.NEGATIVE_INFINITY;
        s.bindMs = Double.NaN;
        String text = JSON.writeValueAsString(LiveSnapshot.toJson(s, T, 10, Double.NaN));
        assertFalse(text.contains("NaN") || text.contains("Infinity"), text);
        JsonNode j = JSON.readTree(text);
        assertTrue(j.path("pad").path("stream").path("median").isNull());
        assertTrue(j.path("frame").path("processingMs").isNull());
    }

    @Test
    void theSnapshotHasEveryFieldTheFrontendReads() throws Exception {
        LiveTrialController.Status s = status("VERIFIED", "OK", "OK", true);
        s.capturePad = 0.98f;
        s.bindMs = 210.0;
        s.captureRoundTripMs = 80.0;
        s.readyMs = 1500L;
        s.spanMs.put("detect", 3.0);
        s.events.add(new LiveTrialController.Event(0, "start", "Trial started"));
        JsonNode j = JSON.readTree(JSON.writeValueAsBytes(LiveSnapshot.toJson(s, T, 100, 20.0)));
        for (String k : new String[] {"trial", "decision", "frame", "pad", "timing", "counters", "camera", "stages", "integrity", "events", "ineligibleCounts"}) {
            assertTrue(j.has(k), k);
        }
        assertEquals(8, j.path("stages").size());
        assertEquals(11, j.path("integrity").size());
        assertEquals("VERIFIED", j.path("decision").path("state").asText());
        assertEquals("verdict text", j.path("decision").path("verdict").asText(), "the engine's wording is passed through unchanged");
        assertTrue(j.path("decision").path("final").asBoolean());
        assertEquals(1, j.path("events").size());
    }
}
