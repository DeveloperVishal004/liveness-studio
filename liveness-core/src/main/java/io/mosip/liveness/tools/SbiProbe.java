package io.mosip.liveness.tools;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.pipeline.LiveStreamRun;
import io.mosip.liveness.sbi.Iso19794FaceRecord;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.sbi.SbiClient;
import io.mosip.liveness.vision.Phase0Models;

import java.io.InputStream;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Characterises a real (or mock) SBI face device for Phase 0:
 * <ol>
 *   <li>discovery and device info (certification level, purpose, digitalId; signatures checked if --trust given);</li>
 *   <li>a timed STREAM run through the production threading model (fps, jitter, JPEG quality, corrupt/frozen
 *       frames, stalls, face size/quality, per-stage latency);</li>
 *   <li>a concurrent RCAPTURE in the middle of the stream: does the stream keep flowing, how long does capture take,
 *       is the transactionId echoed, what is the signed timestamp skew, what is the capture image format/size, and
 *       does the full {@link CaptureBinder} bind it;</li>
 *   <li>optionally (--flash) the sensor-to-host latency with a screen-flash rig.</li>
 * </ol>
 * Thresholds in the "checks" section are provisional Phase-0 criteria, not product requirements.
 */
final class SbiProbe {
    private SbiProbe() {}

    static String deviceSerial(JsonNode infoResponse) throws Exception {
        JsonNode info = JwsVerifier.unverifiedPayload(infoResponse.get(0).path("deviceInfo").asText());
        String digitalId = info.path("digitalId").asText();
        return JwsVerifier.unverifiedPayload(digitalId).path("serialNo").asText();
    }

    static Map<String, Object> run(Phase0Cli.Args a) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        java.util.List<java.nio.file.Path> crls = new ArrayList<>();
        if (a.has("crl")) {
            for (String c : a.getList("crl")) {
                crls.add(Paths.get(c));
            }
        }
        JwsVerifier trust = a.has("trust") ? JwsVerifier.fromPem(Paths.get(a.get("trust")), crls) : null;
        r.put("revocation_checked", trust != null && trust.revocationChecked());
        List<Integer> ports = new ArrayList<>();
        if (a.has("port")) {
            ports.add(a.getInt("port", 4501));
        } else {
            for (int p = 4501; p <= 4600; p++) {
                ports.add(p);
            }
        }
        SbiClient sbi = null;
        List<Map<String, Object>> found = new ArrayList<>();
        for (int p : ports) {
            SbiClient c = new SbiClient(p);
            try {
                JsonNode disc = c.discover();
                for (JsonNode d : disc) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("port", p);
                    m.put("deviceStatus", d.path("deviceStatus").asText());
                    m.put("certification", d.path("certification").asText());
                    m.put("purpose", d.path("purpose").asText());
                    m.put("specVersion", d.path("specVersion").toString());
                    found.add(m);
                }
                if (sbi == null) {
                    sbi = c;
                }
            } catch (Exception ignored) {
                // nothing listening on this port
            }
        }
        r.put("discovery", found);
        if (sbi == null) {
            r.put("error", "no SBI device found on " + (ports.size() == 1 ? "port " + ports.get(0) : "ports 4501-4600"));
            return r;
        }

        Map<String, Object> infoNote = new LinkedHashMap<>();
        JsonNode infoResp = sbi.info();
        JsonNode info = Phase0Cli.verifiedOrUnverified(infoResp.get(0).path("deviceInfo").asText(), trust, infoNote);
        Map<String, Object> idNote = new LinkedHashMap<>();
        JsonNode digitalId = Phase0Cli.verifiedOrUnverified(info.path("digitalId").asText(), trust, idNote);
        Map<String, Object> dev = new LinkedHashMap<>();
        dev.put("deviceInfo_signature", infoNote.get("signature"));
        dev.put("digitalId_signature", idNote.get("signature"));
        dev.put("certification", info.path("certification").asText());
        dev.put("purpose", info.path("purpose").asText());
        dev.put("deviceStatus", info.path("deviceStatus").asText());
        dev.put("serviceVersion", info.path("serviceVersion").asText());
        dev.put("specVersion", info.path("specVersion").toString());
        dev.put("firmware", info.path("firmware").asText());
        // deviceCode may be a per-device registration code: stored only as a hash prefix, like the serial number
        dev.put("deviceCode_sha256_prefix", CaptureBinderAccess.sha256Prefix(info.path("deviceCode").asText()));
        dev.put("deviceProvider", digitalId.path("deviceProvider").asText());
        dev.put("deviceProviderId", digitalId.path("deviceProviderId").asText());
        dev.put("env", info.path("env").asText());
        dev.put("make", digitalId.path("make").asText());
        dev.put("model", digitalId.path("model").asText());
        dev.put("type", digitalId.path("type").asText());
        dev.put("deviceSubType", digitalId.path("deviceSubType").asText());
        dev.put("serialNo_sha256_prefix", CaptureBinderAccess.sha256Prefix(digitalId.path("serialNo").asText()));
        r.put("device", dev);
        String serial = digitalId.path("serialNo").asText();

        long seconds = a.getLong("seconds", 20);
        boolean doCapture = !a.has("no-capture");
        try (Phase0Models models = Phase0Cli.models(a)) {
            FramePipeline pipe = new FramePipeline(models, Phase0Cli.pipelineConfig(a));
            Instant sessionStart = Instant.now();
            InputStream s = sbi.openStream(serial, "0", seconds * 1000 + 15000);
            LiveStreamRun run = new LiveStreamRun(s, pipe, seconds * 1000, a.getInt("warmup-frames", 10));
            AtomicReference<Map<String, Object>> capture = new AtomicReference<>();
            final SbiClient sbiF = sbi;
            Thread capT = null;
            if (doCapture) {
                JsonNode specs = info.path("specVersion");
                String specVersion = specs.isArray() && specs.size() > 0 ? specs.get(specs.size() - 1).asText() : specs.asText("1.0");
                String env = a.get("env", info.path("env").asText("Developer"));
                String purpose = a.get("purpose", info.path("purpose").asText("Registration"));
                capT = new Thread(() -> capture.set(concurrentCapture(sbiF, run, pipe, models, trust, a, serial,
                        digitalId, sessionStart, seconds, specVersion, env, purpose)), "phase0-rcapture");
                capT.setDaemon(true);
                capT.start();
            }
            run.run();
            if (capT != null) {
                capT.join();          // the binder uses the same sessions; never close them under it (R10)
            }
            pipe.close();
            Map<String, Object> rep = run.report();
            r.put("stream", rep);
            if (doCapture) {
                r.put("concurrent_rcapture", capture.get() == null ? "did not complete" : capture.get());
            }
            Map<String, Object> checks = checks(rep, capture.get());
            r.put("checks", checks);
            r.put("probe_summary", summary(dev, rep, capture.get(), checks));
            r.put("models", models.versions);
        }
        if (a.has("flash")) {
            r.put("flash_latency", FlashRig.measure(sbi, serial, a.getInt("flash-cycles", 10)));
        }
        return r;
    }

    private static Map<String, Object> concurrentCapture(SbiClient sbi, LiveStreamRun run, FramePipeline pipe, Phase0Models models,
                                                         JwsVerifier trust, Phase0Cli.Args a, String serial,
                                                         JsonNode digitalId, Instant sessionStart, long seconds,
                                                         String specVersion, String env, String purpose) {
        Map<String, Object> m = new LinkedHashMap<>();
        try {
            Thread.sleep(seconds * 1000 / 2);
            List<float[]> embs = pipe.recentEmbeddings(10);
            int framesBefore = run.evidence.size();
            long rxBefore = run.interArrival.count();
            String txn = SbiClient.newTransactionId();
            long t0 = System.nanoTime();
            boolean legacy = "legacy".equals(a.get("request-format", "sbi10"));
            Map<String, Object> reqInfo = new LinkedHashMap<>();
            reqInfo.put("format", legacy ? "legacy (Phase-0 mock shape)" : "sbi10 (desktop client shape)");
            reqInfo.put("specVersion", legacy ? "0.9.5" : specVersion);
            reqInfo.put("env", env);
            reqInfo.put("purpose", purpose);
            m.put("rcapture_request", reqInfo);
            byte[] resp = legacy
                    ? sbi.rcaptureFace(txn, env, purpose, a.getLong("capture-timeout-ms", 10000), a.getLong("capture-time-ms", 3000), null)
                    : sbi.rcaptureFaceSbi10(txn, env, purpose, specVersion, serial, a.getLong("capture-timeout-ms", 10000));
            long t1 = System.nanoTime();
            Instant hostNow = Instant.now();
            // the whole RCAPTURE must lie inside the stream run, or frames-during are undercounted
            m.put("capture_ended_before_stream_end", Duration.between(sessionStart, hostNow).toMillis() < seconds * 1000);
            m.put("rcapture_ms", Math.round((t1 - t0) / 1e6));
            m.put("stream_frames_received_during_capture", run.interArrival.count() - rxBefore);
            m.put("frames_processed_during_capture", run.evidence.size() - framesBefore);
            JsonNode root = Phase0Cli.JSON.readTree(resp);
            JsonNode bio = root.path("biometrics").get(0);
            m.put("device_error_code", bio.path("error").path("errorCode").asText());
            JsonNode payload = JwsVerifier.unverifiedPayload(bio.path("data").asText());
            m.put("transactionId_echoed", txn.equals(payload.path("transactionId").asText(null)));
            String rawTs = payload.path("timestamp").asText();
            m.put("signed_timestamp_format", timestampFormat(rawTs));
            Instant ts = io.mosip.liveness.binding.CaptureBinderAccess.parseTimestamp(rawTs);
            m.put("signed_timestamp_minus_host_ms", Duration.between(hostNow, ts).toMillis());
            byte[] iso = Base64.getUrlDecoder().decode(payload.path("bioValue").asText().replace("=", ""));
            m.put("bioValue_bytes", iso.length);
            try {
                Iso19794FaceRecord rec = Iso19794FaceRecord.parse(iso);
                m.put("iso_image_type", rec.imageDataType);
                m.put("iso_image_size", rec.width + "x" + rec.height);
                m.put("iso_image_bytes", rec.imageData.length);
                io.mosip.liveness.vision.BgrImage capImg = new io.mosip.liveness.vision.ImageDecoder().decode(rec.imageData);
                java.util.List<io.mosip.liveness.vision.Face> capFaces = models.detector.detect(capImg);
                m.put("capture_faces_detected", capFaces.size());
                if (capFaces.size() == 1) {
                    m.put("capture_face_height_px", Math.round(capFaces.get(0).h));
                }
            } catch (IllegalArgumentException e) {
                m.put("iso_parse_error", e.getMessage());
            }
            m.put("stream_embeddings_available", embs.size());
            // B1 draft (docs/phase1/SBI_INTEGRATION_PLAN.md §3): does the device attach a stream statement?
            String st = root.path("biometrics").path(0).path("additionalInfo").path(io.mosip.liveness.streamauth.StreamDigest.ADDITIONAL_INFO_KEY).asText(null);
            m.put("b1_stream_statement_present", st != null && !st.isEmpty());
            if (st != null && !st.isEmpty()) {
                m.put("b1_stream_statement_chars", st.length());
            }
            if (trust != null) {
                CaptureBinder.SessionContext ctx = new CaptureBinder.SessionContext(txn, serial,
                        digitalId.path("make").asText(null), digitalId.path("model").asText(null), sessionStart, embs);
                // Same response under both capture-PAD rules (each binder has its own replay cache).
                for (String rule : BindScenarios.RULES) {
                    CaptureBinder binder = new CaptureBinder(trust, trust,
                            new io.mosip.liveness.binding.VisionCaptureAnalyzer(models), BindScenarios.policy(rule));
                    BindingResult b = binder.bind(resp, ctx, Instant.now());
                    m.put("binding_" + rule, Phase0Cli.bindingMap(b));
                }
            } else {
                m.put("binding", "not evaluated: signature trust anchor not provided (--trust)");
            }
        } catch (Exception e) {
            m.put("error", e.toString());
        }
        return m;
    }

    /** Exactly the fields of docs/phase1/DEVICE_PROBE_RESULT_TEMPLATE.md for one run (no identifiers beyond hash prefixes). */
    @SuppressWarnings("unchecked")
    static Map<String, Object> summary(Map<String, Object> dev, Map<String, Object> stream, Map<String, Object> cap,
                                       Map<String, Object> checks) {
        Map<String, Object> s = new LinkedHashMap<>();
        for (String k : new String[] {"make", "model", "serviceVersion", "firmware", "specVersion", "certification",
                "serialNo_sha256_prefix", "deviceCode_sha256_prefix"}) {
            s.put(k, dev.get(k));
        }
        Map<String, Object> acq = (Map<String, Object>) stream.get("acquisition");
        s.put("measured_fps", acq == null ? null : acq.get("measured_fps"));
        s.put("verdict", checks.get("stream_during_rcapture_verdict"));
        s.put("device_error_code", cap == null ? null : cap.get("device_error_code"));
        s.put("rcapture_ms", cap == null ? null : cap.get("rcapture_ms"));
        s.put("rcapture_request", cap == null ? null : cap.get("rcapture_request"));
        s.put("transactionId_echoed", checks.get("rcapture_echoes_transactionId"));
        s.put("timestamp_spec_format", checks.get("signed_timestamp_format_is_spec_pattern"));
        s.put("timestamp_within_120s", checks.get("signed_timestamp_within_120s_of_host"));
        s.put("signed_timestamp_minus_host_ms", cap == null ? null : cap.get("signed_timestamp_minus_host_ms"));
        s.put("b1_statement_present", cap == null ? null : cap.get("b1_stream_statement_present"));
        return s;
    }

    /**
     * CONTINUOUS / PAUSES / PARTIAL, or INCONCLUSIVE with the reason (docs/phase1/DEVICE_PROBE_RUNBOOK.md §5).
     * Order matters: anything that makes the frame count unreliable is checked first.
     */
    static String continuityVerdict(double fps, Object streamEnd, Map<String, Object> cap, long got, double expected) {
        Object err = cap.get("device_error_code");
        if (err != null && !"0".equals(String.valueOf(err))) {
            return "INCONCLUSIVE: RCAPTURE returned device error " + err;
        }
        if (Boolean.FALSE.equals(cap.get("capture_ended_before_stream_end"))) {
            return "INCONCLUSIVE: RCAPTURE outlasted the stream run (increase --seconds)";
        }
        if (!"duration elapsed".equals(streamEnd)) {
            return "INCONCLUSIVE: stream ended early (" + streamEnd + ")";
        }
        if (fps < 3 * 0.97) {
            return String.format("INCONCLUSIVE: stream below the SBI minimum of 3 fps (%.2f)", fps);
        }
        if (got < 0) {
            return "INCONCLUSIVE: frame count during RCAPTURE not recorded";   // missing data is never a PAUSES verdict
        }
        if (Double.isNaN(expected) || expected < 4) {
            return String.format("INCONCLUSIVE: capture too short to judge (~%.1f frames expected)", expected);
        }
        if (got >= 2 && got >= 0.5 * expected) {
            return String.format("CONTINUOUS (%d of ~%.0f)", got, expected);
        }
        if (got <= 1) {
            return String.format("PAUSES (%d of ~%.0f)", got, expected);
        }
        return String.format("PARTIAL (%d of ~%.0f)", got, expected);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> checks(Map<String, Object> stream, Map<String, Object> cap) {
        Map<String, Object> c = new LinkedHashMap<>();
        Map<String, Object> acq = (Map<String, Object>) stream.get("acquisition");
        Map<String, Object> ev = (Map<String, Object>) stream.get("evidence");
        double fps = ((Number) acq.get("measured_fps")).doubleValue();
        long frames = ((Number) acq.get("frames")).longValue();
        long corrupt = ((Number) acq.get("corrupt_parts")).longValue();
        long frozen = ((Number) acq.get("identical_consecutive_frames")).longValue();
        long stalls = ((Number) acq.get("stalls_over_500ms")).longValue();
        double eligibleRatio = ((Number) ev.get("eligible_ratio")).doubleValue();
        Map<String, Object> fh = (Map<String, Object>) ev.get("face_height_px");
        double faceH = fh.containsKey("p50") ? ((Number) fh.get("p50")).doubleValue() : 0;
        c.put("note", "PROVISIONAL Phase-0 criteria; see docs/phase0/PHASE0_REPORT.md for derivation");
        // 3% tolerance: a nominal 15 fps device measured 14.99 over 20 s (R13); thresholds are nominal rates.
        c.put("fps_at_least_5_for_passive", pass(fps >= 5 * 0.97, String.format("%.2f fps", fps)));
        c.put("fps_at_least_15_for_blink_challenge", pass(fps >= 15 * 0.97, String.format("%.2f fps", fps)));
        c.put("corrupt_frames_under_1pct", pass(frames > 0 && corrupt < 0.01 * (frames + corrupt), corrupt + " corrupt"));
        c.put("no_frozen_frames", pass(frozen == 0, frozen + " identical consecutive"));
        c.put("no_stalls_over_500ms", pass(stalls == 0, stalls + " stalls"));
        Object end = acq.get("end_reason");
        c.put("stream_lasted_full_duration", pass("duration elapsed".equals(end), String.valueOf(end)));
        c.put("eligible_ratio_at_least_0.6_with_cooperative_subject", pass(eligibleRatio >= 0.6, Double.toString(eligibleRatio)));
        c.put("face_height_p50_at_least_100px", pass(faceH >= 100, faceH + " px"));
        Object res = acq.get("resolutions_sampled");
        c.put("no_exif_orientation_tag", pass(res == null || !res.toString().contains("EXIF-orientation"), String.valueOf(res)));
        if (cap == null) {
            c.put("stream_during_rcapture_verdict", "INCONCLUSIVE: no RCAPTURE (--no-capture, or it did not complete)");
        } else if (cap.containsKey("error")) {
            c.put("stream_during_rcapture_verdict", "INCONCLUSIVE: RCAPTURE failed: " + cap.get("error"));
        }
        if (cap != null && !cap.containsKey("error")) {
            // Continuous = at least half the frames the measured rate predicts for the capture duration (and >= 2).
            // "> 0" misclassified a pausing device as continuous: 1 in-flight frame arrives after the request (R35).
            Object during = cap.get("stream_frames_received_during_capture");
            Object capMs = cap.get("rcapture_ms");
            double expected = capMs instanceof Number ? fps * ((Number) capMs).doubleValue() / 1000.0 : Double.NaN;
            long got = during instanceof Number ? ((Number) during).longValue() : -1;
            String verdict = continuityVerdict(fps, end, cap, got, expected);
            c.put("stream_during_rcapture_verdict", verdict);
            // The PASS/FAIL line is DERIVED from the verdict, so an INCONCLUSIVE run can never read as PASS or FAIL.
            c.put("stream_continues_during_rcapture", verdict.startsWith("CONTINUOUS") ? "PASS (" + verdict + ")"
                    : verdict.startsWith("PAUSES") || verdict.startsWith("PARTIAL") ? "FAIL (" + verdict + ")"
                    : "INCONCLUSIVE (see stream_during_rcapture_verdict)");
            c.put("rcapture_echoes_transactionId", pass(Boolean.TRUE.equals(cap.get("transactionId_echoed")), ""));
            Object fmt = cap.get("signed_timestamp_format");
            c.put("signed_timestamp_format_is_spec_pattern", pass(fmt != null && fmt.toString().contains("SBI spec"), String.valueOf(fmt)));
            Object skew = cap.get("signed_timestamp_minus_host_ms");
            c.put("signed_timestamp_within_120s_of_host", pass(skew instanceof Number && Math.abs(((Number) skew).longValue()) <= 120000, String.valueOf(skew)));
            Object b = cap.get("binding_" + BindScenarios.RULES[0]);
            if (b instanceof Map) {
                // Device check = the rule-independent binding chain (signature, nonce, time, device, format, face, subject).
                // UNCERTAIN/PAD_UNCERTAIN under the conservative rule is a PAD-calibration question, not a binding failure.
                Map<String, Object> bm = (Map<String, Object>) b;
                boolean chainOk = "BOUND".equals(bm.get("outcome"))
                        || ("UNCERTAIN".equals(bm.get("outcome")) && "PAD_UNCERTAIN".equals(bm.get("reason")));
                c.put("capture_passes_rule_independent_binding_checks", pass(chainOk, String.valueOf(b)));
            }
        }
        return c;
    }

    /**
     * Classifies the device's raw RCAPTURE timestamp. The SBI spec and MOSIP MockMDS use yyyy-MM-ddTHH:mm:ssZ; the
     * Registration Client helper parses exactly that pattern, so other formats would break the proposed SBI 1.0 fix.
     */
    static String timestampFormat(String raw) {
        if (raw == null) {
            return "missing";
        }
        if (raw.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z")) {
            return "yyyy-MM-ddTHH:mm:ssZ (SBI spec)";
        }
        if (raw.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{1,9}Z")) {
            return "yyyy-MM-ddTHH:mm:ss.fffZ (fractional seconds; NOT the spec pattern)";
        }
        if (raw.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?[+-]\\d{2}:\\d{2}")) {
            return "ISO-8601 with offset (NOT the spec pattern)";
        }
        return "other: " + raw.replaceAll("[0-9]", "9");
    }

    private static String pass(boolean ok, String detail) {
        return (ok ? "PASS" : "FAIL") + (detail.isEmpty() ? "" : " (" + detail + ")");
    }

    /** Small helper so serial numbers are never written to reports in clear. */
    static final class CaptureBinderAccess {
        static String sha256Prefix(String s) {
            try {
                byte[] h = java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 6; i++) {
                    sb.append(String.format("%02x", h[i]));
                }
                return sb.toString();
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
