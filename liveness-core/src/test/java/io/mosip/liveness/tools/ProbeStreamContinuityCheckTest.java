package io.mosip.liveness.tools;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The probe's {@code stream_continues_during_rcapture} check (R35): a device that pauses its stream during RCAPTURE must
 * not pass because one in-flight frame arrives after the request. This check is the first real-device measurement in
 * docs/phase1/SBI_INTEGRATION_PLAN.md §8. [CODE]
 */
class ProbeStreamContinuityCheckTest {
    static Map<String, Object> stream(double fps) {
        Map<String, Object> acq = new LinkedHashMap<>();
        acq.put("measured_fps", fps);
        acq.put("frames", 300L);
        acq.put("corrupt_parts", 0L);
        acq.put("identical_consecutive_frames", 0L);
        acq.put("stalls_over_500ms", 0L);
        acq.put("end_reason", "duration elapsed");
        Map<String, Object> fh = new LinkedHashMap<>();
        fh.put("p50", 150.0);
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("eligible_ratio", 0.9);
        ev.put("face_height_px", fh);
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("acquisition", acq);
        s.put("evidence", ev);
        return s;
    }

    static String verdict(double fps, long framesDuring, long rcaptureMs) {
        Map<String, Object> cap = new LinkedHashMap<>();
        cap.put("stream_frames_received_during_capture", framesDuring);
        cap.put("rcapture_ms", rcaptureMs);
        return String.valueOf(SbiProbe.checks(stream(fps), cap).get("stream_continues_during_rcapture"));
    }

    @Test
    void oneInFlightFrameDuringAThreeSecondCaptureIsAPause() {
        assertTrue(verdict(15, 1, 3000).startsWith("FAIL"), verdict(15, 1, 3000));
        assertTrue(verdict(15, 0, 3000).startsWith("FAIL"));
        assertTrue(verdict(15, 10, 3000).startsWith("FAIL"), "10 of ~45 is a partial pause");
    }

    @Test
    void framesAtTheMeasuredRateDuringCaptureAreContinuous() {
        assertTrue(verdict(15, 45, 3000).startsWith("PASS"), verdict(15, 45, 3000));
        assertTrue(verdict(15, 23, 3000).startsWith("PASS"));
        // ~3 expected frames is too few to tell a pause from jitter: INCONCLUSIVE, never PASS/FAIL
        assertTrue(verdict(3, 2, 1000).startsWith("INCONCLUSIVE"), "low-fps short capture: 2 of ~3");
        assertTrue(verdict(5, 5, 2000).startsWith("PASS"), "low-fps device: 5 of ~10");
    }

    static String v(double fps, Object end, long got, double expected, String err, Boolean inside) {
        Map<String, Object> cap = new LinkedHashMap<>();
        if (err != null) {
            cap.put("device_error_code", err);
        }
        if (inside != null) {
            cap.put("capture_ended_before_stream_end", inside);
        }
        return SbiProbe.continuityVerdict(fps, end, cap, got, expected);
    }

    @Test
    void verdictCoversEveryOutcome() {
        String ok = "duration elapsed";
        assertTrue(v(15, ok, 44, 45, "0", true).startsWith("CONTINUOUS"));
        assertTrue(v(15, ok, 1, 45, "0", true).startsWith("PAUSES"));
        assertTrue(v(15, ok, 0, 45, "0", true).startsWith("PAUSES"));
        assertTrue(v(15, ok, 10, 45, "0", true).startsWith("PARTIAL"));
        assertTrue(v(15, ok, 44, 45, "702", true).startsWith("INCONCLUSIVE: RCAPTURE returned device error"));
        assertTrue(v(15, ok, 0, 45, "0", false).startsWith("INCONCLUSIVE: RCAPTURE outlasted"));
        assertTrue(v(15, "disconnected", 0, 45, "0", true).startsWith("INCONCLUSIVE: stream ended early"));
        assertTrue(v(2, ok, 0, 6, "0", true).startsWith("INCONCLUSIVE: stream below"));
        assertTrue(v(15, ok, 0, 3, "0", true).startsWith("INCONCLUSIVE: capture too short"));
    }

    @Test
    void sbi10RequestUsesTheClientsPreviousHash() {
        assertTrue(io.mosip.liveness.sbi.SbiClientAccess.emptySha256Hex()
                .equals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"));
    }

    static Map<String, Object> checks(double fps, Map<String, Object> cap) {
        return SbiProbe.checks(stream(fps), cap);
    }

    static Map<String, Object> cap(Object err, Object frames, Object ms, Object inside) {
        Map<String, Object> c = new LinkedHashMap<>();
        if (err != null) c.put("device_error_code", err);
        if (frames != null) c.put("stream_frames_received_during_capture", frames);
        if (ms != null) c.put("rcapture_ms", ms);
        if (inside != null) c.put("capture_ended_before_stream_end", inside);
        return c;
    }

    /** Item 4: no INCONCLUSIVE condition may surface as PASS/FAIL or as a CONTINUOUS/PAUSES verdict. */
    @Test
    void inconclusiveRunsNeverReadAsPassFailContinuousOrPauses() {
        Object[][] inconclusive = {
            {15.0, cap("702", 45L, 3000L, true)},          // device error while frames kept flowing (old code: PASS)
            {15.0, cap("702", 0L, 3000L, true)},           // device error, no frames (old code: FAIL)
            {15.0, cap("0", 0L, 3000L, false)},            // capture outlasted the stream
            {15.0, cap("0", 45L, null, true)},             // rcapture_ms missing
            {15.0, cap("0", null, 3000L, true)},           // frame count missing
            {2.0, cap("0", 0L, 3000L, true)},              // below 3 fps
            {Double.NaN, cap("0", 0L, 3000L, true)},       // fps unknown
            {15.0, cap("0", 0L, 100L, true)},              // capture too short
        };
        for (Object[] c : inconclusive) {
            @SuppressWarnings("unchecked") Map<String, Object> ch = checks((Double) c[0], (Map<String, Object>) c[1]);
            String verdict = String.valueOf(ch.get("stream_during_rcapture_verdict"));
            String legacy = String.valueOf(ch.get("stream_continues_during_rcapture"));
            assertTrue(verdict.startsWith("INCONCLUSIVE"), c[1] + " -> " + verdict);
            assertTrue(legacy.startsWith("INCONCLUSIVE"), c[1] + " -> " + legacy);
        }
        Map<String, Object> ch = SbiProbe.checks(stream(15), null);
        assertTrue(String.valueOf(ch.get("stream_during_rcapture_verdict")).startsWith("INCONCLUSIVE"));
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("error", "java.io.IOException: refused");
        assertTrue(String.valueOf(SbiProbe.checks(stream(15), err).get("stream_during_rcapture_verdict")).startsWith("INCONCLUSIVE"));
    }

    @Test
    void passFailLineAgreesWithTheVerdict() {
        assertTrue(String.valueOf(checks(15, cap("0", 44L, 3000L, true)).get("stream_continues_during_rcapture")).startsWith("PASS (CONTINUOUS"));
        assertTrue(String.valueOf(checks(15, cap("0", 1L, 3000L, true)).get("stream_continues_during_rcapture")).startsWith("FAIL (PAUSES"));
        assertTrue(String.valueOf(checks(15, cap("0", 10L, 3000L, true)).get("stream_continues_during_rcapture")).startsWith("FAIL (PARTIAL"));
    }
}
