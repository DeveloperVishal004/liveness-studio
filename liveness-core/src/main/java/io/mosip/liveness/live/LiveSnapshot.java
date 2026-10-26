package io.mosip.liveness.live;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns a {@link LiveTrialController.Status} into the JSON the frontend renders. Pure: it adds NO evidence and takes NO
 * decision. The decision, its reason and every score are passed through from the engine; the per-stage and per-check
 * states are derived only from things the engine actually did, using the fixed order in which
 * {@code CaptureBinder.bind} performs its checks (a check is "passed" only if a later check was reached or the capture
 * was bound; everything after the first failure is "not_checked").
 *
 * <p>Stage states: pending, active, passed, attention (not a failure: more evidence or a retry is needed), failed, skipped.
 * Check states: passed, failed, not_checked, unavailable, not_applicable.
 */
public final class LiveSnapshot {
    private LiveSnapshot() {}

    /** The thresholds actually in force, read from the engine's own policies (never hard-coded in the UI). */
    public static final class Thresholds {
        public float streamAccept = 0.80f, streamAttack = 0.20f, captureAccept = 0.80f, captureAttack = 0.20f;
        public float subjectMinCosine = 0.50f;
        public double motionTrigger = 0.40;
        public int minFaceHeightPx = 80, minStreamEmbeddings = 3, attackMinFrames = 3;
        public double minSharpness = 15;
    }

    // ---- binder check order (CaptureBinder.bind) -------------------------------------------------------------------------
    static final String[] CHECK_IDS = {"response", "signature", "chain", "replay", "device", "nonce", "timestamp",
            "biometric", "faceCount", "subject"};
    static final String[] CHECK_LABELS = {"Response format", "RS256 signature", "Certificate chain and trust", "Replay protection",
            "Device identity", "Nonce (transaction ID)", "Timestamp window", "Biometric record", "Face count in capture",
            "Stream / capture subject match"};

    /** Index of the first check that did NOT pass for a binder reason (checks before it passed); -1 = all binder checks passed. */
    static int failingCheck(String bindingReason) {
        if (bindingReason == null) {
            return -2;                                                       // no binder result yet
        }
        switch (bindingReason) {
            case "MALFORMED_RESPONSE": case "DEVICE_ERROR": return 0;
            case "BAD_SIGNATURE": return 1;
            case "UNTRUSTED_DEVICE": return 2;
            case "REPLAYED_RESPONSE": return 3;
            case "DIGITAL_ID_INVALID": case "DEVICE_MISMATCH": return 4;
            case "TRANSACTION_ABSENT": case "TRANSACTION_MISMATCH": return 5;
            case "MALFORMED_CONTENT": case "CAPTURE_STALE": case "CAPTURE_FROM_FUTURE": case "CAPTURE_OUTSIDE_WINDOW": return 6;
            case "BAD_BIO_FORMAT": return 7;
            case "NO_FACE": case "MULTIPLE_FACES": return 8;
            case "SUBJECT_MISMATCH": return 9;
            default: return -1;                                              // OK, PAD_ATTACK, PAD_UNCERTAIN, INSUFFICIENT_STREAM_EVIDENCE: the checks above passed
        }
    }

    private static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            Object v = kv[i + 1];
            if ((v instanceof Float && !Float.isFinite((Float) v)) || (v instanceof Double && !Double.isFinite((Double) v))) {
                v = null;                                                    // JSON has no NaN/Infinity: absent, never a made-up number
            }
            out.put((String) kv[i], v);
        }
        return out;
    }

    static boolean captureFailedToRun(LiveTrialController.Status s) {
        return s.detail != null && s.detail.startsWith("RCAPTURE failed");
    }

    static boolean decided(LiveTrialController.Status s) {
        return s.finished() || "CANCELLED".equals(s.state);
    }

    // ---- integrity checks ----------------------------------------------------------------------------------------------
    public static List<Map<String, Object>> integrity(LiveTrialController.Status s) {
        List<Map<String, Object>> out = new ArrayList<>();
        String[] st = new String[CHECK_IDS.length];
        String[] why = new String[CHECK_IDS.length];
        Arrays.fill(st, "not_checked");
        Arrays.fill(why, "");
        String none = !s.captureIssued ? "No signed capture was requested in this trial."
                : "Waiting for the device response.";
        Arrays.fill(why, none);
        if (captureFailedToRun(s)) {
            Arrays.fill(st, "unavailable");
            Arrays.fill(why, s.detail);
        } else if (s.captureIssued && s.bindingReason != null) {
            int f = failingCheck(s.bindingReason);
            boolean engineError = "ENGINE_ERROR".equals(s.bindingReason);
            for (int i = 0; i < CHECK_IDS.length; i++) {
                if (f >= 0 && i == f) {
                    st[i] = "failed";
                    why[i] = "Failed: " + s.bindingReason;
                } else if (f >= 0 && i > f) {
                    st[i] = "not_checked";
                    why[i] = "Not reached: an earlier check failed.";
                } else {                                                      // reached and cleared (before the failure, or no failure)
                    st[i] = "passed";
                    why[i] = "";
                }
            }
            if (f == -1) {                                                    // binder got through every check up to the subject match
                String br = s.bindingReason;
                if (engineError) {
                    for (int i = 8; i < CHECK_IDS.length; i++) {
                        st[i] = "unavailable";
                        why[i] = "The analysis step failed (engine error).";
                    }
                } else if ("PAD_ATTACK".equals(br)) {
                    st[9] = "not_checked";
                    why[9] = "Not reached: capture PAD flagged an attack first.";
                } else if ("INSUFFICIENT_STREAM_EVIDENCE".equals(br)) {
                    st[9] = "not_checked";
                    why[9] = "Not enough stream face samples near the capture (needs at least 3).";
                } else {                                                      // OK or PAD_UNCERTAIN: median match was computed and passed
                    boolean wholeAttempt = "VERIFIED".equals(s.state);
                    if ("SUBJECT_CHANGED".equals(s.reason)) {
                        st[9] = "failed";
                        why[9] = "A face earlier in the attempt did not match the capture (whole-attempt check).";
                    } else if ("OK".equals(br) && !wholeAttempt) {
                        st[9] = "not_checked";
                        why[9] = "The median match passed; the whole-attempt check was not reached (" + s.reason + ").";
                    } else {
                        st[9] = "passed";
                        why[9] = wholeAttempt ? "Every frontal face sample in the attempt matched the capture."
                                : "The median stream face matched the capture.";
                    }
                }
            } else if (f == 9) {
                why[9] = "Stream and capture faces differ (median similarity below the line).";
            }
        }
        for (int i = 0; i < CHECK_IDS.length; i++) {
            out.add(m("id", CHECK_IDS[i], "label", CHECK_LABELS[i], "state", st[i], "detail", why[i]));
        }
        out.add(m("id", "streamAuth", "label", "Signed stream (B1 digest)", "state", "not_applicable",
                "detail", "SBI 1.0 streams are unsigned. The signed-stream prototype is disabled in this build."));
        return out;
    }

    // ---- pipeline stages -------------------------------------------------------------------------------------------------
    private static Map<String, Object> stage(String id, String label, String model, String state, Double ms, String code, String detail) {
        return m("id", id, "label", label, "model", model, "state", state, "durationMs", ms, "reasonCode", code, "detail", detail);
    }

    private static String f2(Float v) {
        return v == null || !Float.isFinite(v) ? "-" : String.format(java.util.Locale.ROOT, "%.2f", v);
    }

    public static List<Map<String, Object>> stages(LiveTrialController.Status s, Thresholds t) {
        List<Map<String, Object>> out = new ArrayList<>();
        boolean idle = s.trial == 0;
        boolean running = s.trialActive;
        boolean done = decided(s);
        int noFace = s.ineligibleCounts.getOrDefault("NO_FACE", 0);
        int multi = s.ineligibleCounts.getOrDefault("MULTIPLE_FACES", 0);
        int oneFace = Math.max(0, s.frames - noFace - multi);

        // 1 face detection
        if (idle || s.frames == 0) {
            out.add(stage("detect", "Face detection", "YuNet", running ? "active" : "pending", null, null,
                    running ? "Waiting for camera frames." : "Starts when a verification begins."));
        } else if (oneFace == 0) {
            out.add(stage("detect", "Face detection", "YuNet", "attention", s.spanMs.get("detect"), noFace >= multi ? "NO_FACE" : "MULTIPLE_FACES",
                    noFace >= multi ? "No face found in " + s.frames + " frames." : "More than one face in view."));
        } else if (running && s.faceCount > 1) {
            out.add(stage("detect", "Face detection", "YuNet", "attention", s.spanMs.get("detect"), "MULTIPLE_FACES", "More than one face in view right now."));
        } else {
            out.add(stage("detect", "Face detection", "YuNet", "passed", s.spanMs.get("detect"), null,
                    "Exactly one face found in " + oneFace + " of " + s.frames + " frames."));
        }

        // 2 quality
        if (idle || s.frames == 0) {
            out.add(stage("quality", "Image-quality gates", "Size, light, sharpness", "pending", null, null, "Checks face size, brightness and sharpness."));
        } else if (s.eligibleFrames == 0) {
            String top = topReason(s, true);
            out.add(stage("quality", "Image-quality gates", "Size, light, sharpness", "attention", s.spanMs.get("quality"), top,
                    top == null ? "No frame was usable yet." : "No frame passed the quality gates (" + top + ")."));
        } else if (running && !s.eligible && s.faceCount == 1) {
            out.add(stage("quality", "Image-quality gates", "Size, light, sharpness", "attention", s.spanMs.get("quality"), s.ineligibleReason,
                    "Latest frame not usable: " + s.ineligibleReason + "."));
        } else {
            out.add(stage("quality", "Image-quality gates", "Size, light, sharpness", "passed", s.spanMs.get("quality"), null,
                    s.eligibleFrames + " of " + s.frames + " frames usable."));
        }

        // 3 passive PAD
        boolean padAttack = "STREAM_PAD_ATTACK".equals(s.reason);
        if (s.eligibleFrames == 0) {
            out.add(stage("pad", "Passive presentation-attack check", "MiniFASNet (public, uncalibrated)", "pending", null, null,
                    "Scores each usable frame once a face passes the quality gates."));
        } else if (padAttack) {
            out.add(stage("pad", "Passive presentation-attack check", "MiniFASNet (public, uncalibrated)", "failed", s.spanMs.get("pad"), "STREAM_PAD_ATTACK",
                    "At least " + t.attackMinFrames + " frames scored below " + f2(t.streamAttack) + " (median " + f2(s.medianPad) + ")."));
        } else if (s.medianPad != null && s.medianPad >= t.streamAccept) {
            out.add(stage("pad", "Passive presentation-attack check", "MiniFASNet (public, uncalibrated)", "passed", s.spanMs.get("pad"), null,
                    "Median stream score " + f2(s.medianPad) + " (accept at " + f2(t.streamAccept) + " or above). An uncalibrated model score, not a probability of identity."));
        } else {
            out.add(stage("pad", "Passive presentation-attack check", "MiniFASNet (public, uncalibrated)", "attention", s.spanMs.get("pad"),
                    done ? "PASSIVE_UNCERTAIN_NO_CHALLENGE" : null,
                    "Median stream score " + f2(s.medianPad) + " is below " + f2(t.streamAccept) + "."));
        }

        // 4 temporal evidence
        if (s.readyMs != null) {
            out.add(stage("temporal", "Temporal evidence", "Motion across frames", "passed", s.readyMs.doubleValue(), null,
                    "Facial movement above the trigger was seen and the session became ready after " + s.readyMs + " ms."));
        } else if ("STATIC_REPLAY_SUSPECT".equals(s.reason)) {
            out.add(stage("temporal", "Temporal evidence", "Motion across frames", "attention", null, "STATIC_REPLAY_SUSPECT",
                    "No facial movement above the trigger. Smiling or speaking helps; blinking alone is too small on many cameras."));
        } else if (s.eligibleFrames == 0 || padAttack) {
            out.add(stage("temporal", "Temporal evidence", "Motion across frames", done ? "skipped" : "pending", null, null,
                    "Looks for natural facial movement once usable frames are scored."));
        } else if (running) {
            out.add(stage("temporal", "Temporal evidence", "Motion across frames", "active", null, null, "Looking for natural facial movement."));
        } else {
            out.add(stage("temporal", "Temporal evidence", "Motion across frames", "attention", null, s.reason,
                    "Not enough usable evidence before the time limit."));
        }

        // 5 signed capture and device integrity
        List<Map<String, Object>> checks = integrity(s);
        String firstFail = null;
        boolean anyPassed = false;
        for (Map<String, Object> c : checks) {
            if ("failed".equals(c.get("state")) && !"subject".equals(c.get("id"))) {
                firstFail = (String) c.get("id");
                break;
            }
            if ("passed".equals(c.get("state"))) {
                anyPassed = true;
            }
        }
        boolean integrityPassed = anyPassed && firstFail == null && isPassed(checks, "faceCount");
        if (captureFailedToRun(s)) {
            out.add(stage("integrity", "Signed capture and device integrity", "RS256, trust chain, nonce, time", "failed", null, "CAPTURE_UNAVAILABLE",
                    s.detail));
        } else if (!s.captureIssued) {
            out.add(stage("integrity", "Signed capture and device integrity", "RS256, trust chain, nonce, time", done ? "skipped" : "pending", null, null,
                    done ? "Not reached: the session never became ready for capture." : "Runs after the passive checks pass."));
        } else if (s.bindingReason == null) {
            out.add(stage("integrity", "Signed capture and device integrity", "RS256, trust chain, nonce, time", "active", s.captureRoundTripMs, null,
                    "Waiting for the signed response and verifying it."));
        } else if (firstFail != null) {
            out.add(stage("integrity", "Signed capture and device integrity", "RS256, trust chain, nonce, time", "failed", s.bindMs, s.bindingReason,
                    "Check failed: " + labelOf(firstFail) + "."));
        } else if (integrityPassed) {
            out.add(stage("integrity", "Signed capture and device integrity", "RS256, trust chain, nonce, time", "passed", s.bindMs, null,
                    "Signature, chain, replay, device, nonce, time, record and face count all passed. This shows the capture channel is intact, not that the face was live."));
        } else {
            out.add(stage("integrity", "Signed capture and device integrity", "RS256, trust chain, nonce, time", "attention", s.bindMs, s.bindingReason, "Verification ended early."));
        }

        // 6 capture PAD
        if (!s.captureIssued || (captureFailedToRun(s))) {
            out.add(stage("capturePad", "Signed-capture PAD gate", "MiniFASNet on the signed image", done ? "skipped" : "pending", null, null,
                    "Scores the signed image itself."));
        } else if (s.capturePad == null) {
            out.add(stage("capturePad", "Signed-capture PAD gate", "MiniFASNet on the signed image", s.bindingReason == null ? "active" : "skipped", null, null,
                    s.bindingReason == null ? "Scoring the signed image." : "Not reached: an integrity check failed first."));
        } else if (s.capturePad < t.captureAttack) {
            out.add(stage("capturePad", "Signed-capture PAD gate", "MiniFASNet on the signed image", "failed", null, "PAD_ATTACK",
                    "Capture score " + f2(s.capturePad) + " is below the attack line " + f2(t.captureAttack) + "."));
        } else if (s.capturePad < t.captureAccept) {
            out.add(stage("capturePad", "Signed-capture PAD gate", "MiniFASNet on the signed image", "attention", null, "PAD_UNCERTAIN",
                    "Capture score " + f2(s.capturePad) + " is between the attack line and the accept gate " + f2(t.captureAccept) + ". Retry required."));
        } else {
            out.add(stage("capturePad", "Signed-capture PAD gate", "MiniFASNet on the signed image", "passed", null, null,
                    "Capture score " + f2(s.capturePad) + " (accept at " + f2(t.captureAccept) + " or above)."));
        }

        // 7 subject consistency
        String subj = (String) checks.get(9).get("state");
        String subjWhy = (String) checks.get(9).get("detail");
        if (!s.captureIssued || captureFailedToRun(s)) {
            out.add(stage("subject", "Stream / capture subject match", "SFace", done ? "skipped" : "pending", null, null,
                    "Compares the face seen on the stream with the face in the signed capture."));
        } else if ("failed".equals(subj)) {
            out.add(stage("subject", "Stream / capture subject match", "SFace", "failed", null,
                    "SUBJECT_CHANGED".equals(s.reason) ? "SUBJECT_CHANGED" : "SUBJECT_MISMATCH", subjWhy));
        } else if ("passed".equals(subj)) {
            out.add(stage("subject", "Stream / capture subject match", "SFace", "passed", null, null, subjWhy));
        } else if ("INSUFFICIENT_STREAM_EVIDENCE".equals(s.bindingReason)) {
            out.add(stage("subject", "Stream / capture subject match", "SFace", "attention", null, "INSUFFICIENT_STREAM_EVIDENCE", subjWhy));
        } else {
            out.add(stage("subject", "Stream / capture subject match", "SFace", s.bindingReason == null ? "pending" : "skipped", null, null, subjWhy));
        }

        // 8 decision
        String ds;
        if (idle || (running && !done)) {
            ds = running ? "active" : "pending";
        } else if ("VERIFIED".equals(s.state)) {
            ds = "passed";
        } else if ("RETRY_PENDING".equals(s.state)) {
            ds = "attention";
        } else if ("CANCELLED".equals(s.state)) {
            ds = "skipped";
        } else {
            ds = "failed";
        }
        out.add(stage("decision", "Engine decision", "Session state machine", ds, null, done ? s.reason : null,
                idle ? "No verification has run." : s.verdict));
        return out;
    }

    private static boolean isPassed(List<Map<String, Object>> checks, String id) {
        for (Map<String, Object> c : checks) {
            if (id.equals(c.get("id"))) {
                return "passed".equals(c.get("state"));
            }
        }
        return false;
    }

    private static String labelOf(String id) {
        for (int i = 0; i < CHECK_IDS.length; i++) {
            if (CHECK_IDS[i].equals(id)) {
                return CHECK_LABELS[i];
            }
        }
        return id;
    }

    private static String topReason(LiveTrialController.Status s, boolean excludeFaceCount) {
        String best = null;
        int n = 0;
        for (Map.Entry<String, Integer> e : s.ineligibleCounts.entrySet()) {
            if (excludeFaceCount && ("NO_FACE".equals(e.getKey()) || "MULTIPLE_FACES".equals(e.getKey()))) {
                continue;
            }
            if (e.getValue() > n) {
                n = e.getValue();
                best = e.getKey();
            }
        }
        return best;
    }

    // ---- the full snapshot -----------------------------------------------------------------------------------------------
    public static Map<String, Object> toJson(LiveTrialController.Status s, Thresholds t, long framesReceived, double lastFrameAgeMs) {
        Map<String, Object> trial = m("id", s.trialId, "number", s.trial, "label", s.label, "active", s.trialActive,
                "unfinished", s.unfinished, "startedAtMs", s.trial == 0 ? null : s.startedAtMs,
                "finishedAtMs", s.finishedAtMs == 0 ? null : s.finishedAtMs, "attempt", s.attempt == 0 ? null : s.attempt,
                "maxAttempts", s.maxAttempts == 0 ? null : s.maxAttempts);
        Map<String, Object> decision = m("state", s.state, "reason", s.reason, "bindingReason", s.bindingReason, "verdict", s.verdict,
                "detail", s.detail, "final", decided(s));
        Map<String, Object> frame = m("width", s.frameWidth, "height", s.frameHeight, "faceCount", s.faceCount, "eligible", s.eligible,
                "ineligibleReason", s.ineligibleReason, "faceBox", s.faceBox, "processingMs", s.frameProcessingMs, "ageMs", s.frameAgeMs);
        Map<String, Object> stream = m("last", s.lastPad, "median", s.medianPad, "min", s.padMin, "max", s.padMax,
                "frames", s.frames, "eligibleFrames", s.eligibleFrames);
        Map<String, Object> pad = m("stream", stream, "capture", m("score", s.capturePad));
        Map<String, Object> timing = m("readyMs", s.readyMs, "captureRoundTripMs", s.captureRoundTripMs, "bindMs", s.bindMs,
                "frameSpansMs", s.spanMs,
                "decisionMs", (s.finishedAtMs != 0 && s.startedAtMs != 0) ? (Object) (s.finishedAtMs - s.startedAtMs) : null);
        Map<String, Object> counters = m("attackEvents", s.attackEvents, "channelEvents", s.channelEvents);
        Map<String, Object> camera = m("framesReceived", framesReceived, "lastFrameAgeMs", lastFrameAgeMs < 0 ? null : (Object) lastFrameAgeMs,
                "streaming", lastFrameAgeMs >= 0 && lastFrameAgeMs < 2500);
        List<Map<String, Object>> events = new ArrayList<>();
        for (LiveTrialController.Event e : s.events) {
            events.add(m("tMs", e.tMs, "type", e.type, "text", e.text));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("trial", trial);
        out.put("decision", decision);
        out.put("frame", frame);
        out.put("pad", pad);
        out.put("timing", timing);
        out.put("counters", counters);
        out.put("camera", camera);
        out.put("ineligibleCounts", s.ineligibleCounts);
        out.put("stages", stages(s, t));
        out.put("integrity", integrity(s));
        out.put("events", events);
        return out;
    }

    public static Map<String, Object> info(Thresholds t, String camera) {
        return m("mode", "real",
                "camera", camera,
                "device", "SBI emulator with TEST keys (not a certified device)",
                "pad", "MiniFASNet V2 + V1SE (public model, not evaluated or calibrated for this setup)",
                "disclosure", "Single trials are anecdotes, not accuracy measurements. A valid signature shows the capture channel is intact; it does not show the subject was live.",
                "thresholds", m("streamAccept", t.streamAccept, "streamAttack", t.streamAttack, "captureAccept", t.captureAccept,
                        "captureAttack", t.captureAttack, "subjectMinCosine", t.subjectMinCosine, "motionTrigger", t.motionTrigger,
                        "minFaceHeightPx", t.minFaceHeightPx, "minSharpness", t.minSharpness, "minStreamEmbeddings", t.minStreamEmbeddings,
                        "attackMinFrames", t.attackMinFrames));
    }
}
