package io.mosip.liveness.tools;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.binding.VisionCaptureAnalyzer;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.pipeline.LatencyStats;
import io.mosip.liveness.pipeline.LiveStreamRun;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.sbi.SbiClient;
import io.mosip.liveness.vision.Phase0Models;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Runs the capture-binding scenario matrix end to end against the mock SBI (which selects its RCAPTURE behaviour per
 * request from {@code customOpts.phase0CaptureMode}). A live stream session runs throughout, as in the Registration
 * Client. <b>Every RCAPTURE response is bound under both capture-PAD rules</b> - the conservative accept gate (default)
 * and the PROPOSED veto-only rule (D4) - so the two are compared on byte-identical inputs. Each rule has its own binder
 * (own replay cache) and sees the same sequence of responses.
 *
 * <p>Security criterion per rule: an attack/fault scenario must never be BOUND; the genuine capture may be BOUND or
 * UNCERTAIN (UNCERTAIN costs usability, not security). Named swaps ({@code --swaps a,b} with mock {@code --swap a=PATH})
 * are reported without expectations: they are the cases that discriminate between the rules.
 */
final class BindScenarios {
    private BindScenarios() {}

    static final String GENUINE = "best";
    /** Scenarios with a fixed expected rejection (rule-independent unless noted). */
    static final Map<String, List<String>> EXPECTED = new LinkedHashMap<>();
    static {
        EXPECTED.put(GENUINE, Arrays.asList("BOUND/OK", "UNCERTAIN/PAD_UNCERTAIN"));
        EXPECTED.put("swap", Arrays.asList("ATTACK/PAD_ATTACK", "UNCERTAIN/PAD_UNCERTAIN", "REJECTED/SUBJECT_MISMATCH"));
        EXPECTED.put("swap-alt", Arrays.asList("REJECTED/SUBJECT_MISMATCH", "ATTACK/PAD_ATTACK", "UNCERTAIN/PAD_UNCERTAIN"));
        EXPECTED.put("replay", Arrays.asList("REJECTED/REPLAYED_RESPONSE"));
        EXPECTED.put("replay@fresh-binder", Arrays.asList("REJECTED/TRANSACTION_MISMATCH"));
        EXPECTED.put("stale", Arrays.asList("REJECTED/CAPTURE_STALE"));
        EXPECTED.put("txn-mismatch", Arrays.asList("REJECTED/TRANSACTION_MISMATCH"));
        EXPECTED.put("txn-omit", Arrays.asList("REJECTED/TRANSACTION_ABSENT"));   // device fault in the session (2026-10-24)
        EXPECTED.put("tamper", Arrays.asList("REJECTED/BAD_SIGNATURE"));
        EXPECTED.put("untrusted-key", Arrays.asList("REJECTED/UNTRUSTED_DEVICE"));
        EXPECTED.put("other-device", Arrays.asList("REJECTED/DEVICE_MISMATCH"));
        EXPECTED.put("error", Arrays.asList("REJECTED/DEVICE_ERROR"));
    }

    static final String[] RULES = {"old_accept_gate", "proposed_veto_only"};

    static CaptureBinder.Policy policy(String rule) {
        return rule.equals(RULES[0]) ? CaptureBinder.Policy.conservativeAcceptGate() : CaptureBinder.Policy.proposedVetoOnly();
    }

    static Map<String, Object> run(Phase0Cli.Args a) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        Path trust = Paths.get(a.get("trust"));
        JwsVerifier verifier = JwsVerifier.fromPem(trust);
        SbiClient sbi = new SbiClient(a.getInt("port", 4501));
        JsonNode infoResp = sbi.info();
        JsonNode info = verifier.verify(infoResp.get(0).path("deviceInfo").asText(), new java.util.Date()).payload;
        JsonNode digitalId = verifier.verify(info.path("digitalId").asText(), new java.util.Date()).payload;
        String serial = digitalId.path("serialNo").asText();
        List<String> swaps = a.has("swaps") ? Arrays.asList(a.get("swaps").split(",")) : Collections.emptyList();

        try (Phase0Models models = Phase0Cli.models(a)) {
            FramePipeline.Config cfg = Phase0Cli.pipelineConfig(a);
            cfg.embedEvery = 3;
            FramePipeline pipe = new FramePipeline(models, cfg);
            Instant sessionStart = Instant.now();
            long seconds = a.getLong("seconds", 25);
            InputStream s = sbi.openStream(serial, "0", seconds * 1000 + 10000);
            LiveStreamRun run = new LiveStreamRun(s, pipe, seconds * 1000, 0);
            VisionCaptureAnalyzer analyzer = new VisionCaptureAnalyzer(models);
            Map<String, CaptureBinder> shared = new LinkedHashMap<>();
            Map<String, CaptureBinder> fresh = new LinkedHashMap<>();
            for (String rule : RULES) {
                shared.put(rule, new CaptureBinder(verifier, verifier, analyzer, policy(rule)));
                fresh.put(rule, new CaptureBinder(verifier, verifier, analyzer, policy(rule)));
            }
            List<Map<String, Object>> results = new ArrayList<>();
            Map<String, int[]> securityPass = new LinkedHashMap<>();
            for (String rule : RULES) {
                securityPass.put(rule, new int[2]); // {passed, total}
            }
            Map<String, LatencyStats> bindLatency = new LinkedHashMap<>();
            Map<String, Map<String, Integer>> genuineOutcomes = new LinkedHashMap<>();
            for (String rule : RULES) {
                bindLatency.put(rule, new LatencyStats());
                genuineOutcomes.put(rule, new TreeMap<>());
            }
            List<Float> padOnGenuineCapture = new ArrayList<>();
            Thread t = new Thread(() -> {
                try {
                    Thread.sleep(3000);
                    List<String> scenarios = new ArrayList<>(EXPECTED.keySet());
                    scenarios.remove("replay@fresh-binder");
                    for (String sw : swaps) {
                        scenarios.add("swap:" + sw);
                    }
                    for (String scenario : scenarios) {
                        String txn = SbiClient.newTransactionId();
                        byte[] resp = sbi.rcaptureFace(txn, "Developer", "Registration", 10000, 300, Phase0Cli.customMode(scenario));
                        CaptureBinder.SessionContext ctx = ctx(txn, serial, digitalId, sessionStart, pipe.recentEmbeddings(10));
                        results.add(entry(scenario, shared, resp, ctx, securityPass));
                        if (scenario.equals("replay")) {
                            results.add(entry("replay@fresh-binder", fresh, resp, ctx, securityPass));
                        }
                    }
                    int repeat = a.getInt("repeat-best", 0);
                    for (int i = 0; i < repeat; i++) {
                        String txn = SbiClient.newTransactionId();
                        byte[] resp = sbi.rcaptureFace(txn, "Developer", "Registration", 10000, 200, Phase0Cli.customMode(GENUINE));
                        CaptureBinder.SessionContext ctx = ctx(txn, serial, digitalId, sessionStart, pipe.recentEmbeddings(10));
                        for (String rule : RULES) {
                            BindingResult b = shared.get(rule).bind(resp, ctx, Instant.now());
                            bindLatency.get(rule).record(b.elapsedNanos);
                            genuineOutcomes.get(rule).merge(b.outcome + "/" + b.reason, 1, Integer::sum);
                            if (rule.equals(RULES[0]) && b.padRealProbability != null) {
                                padOnGenuineCapture.add(b.padRealProbability);
                            }
                        }
                    }
                } catch (Exception e) {
                    Map<String, Object> err = new LinkedHashMap<>();
                    err.put("error", e.toString());
                    results.add(err);
                }
            }, "phase0-bind-scenarios");
            t.setDaemon(true);
            t.start();
            run.run();
            t.join();                 // scenario thread uses the sessions; never close them under it (R10)
            pipe.close();
            r.put("scenarios", results);
            Map<String, Object> sec = new LinkedHashMap<>();
            for (String rule : RULES) {
                int[] p = securityPass.get(rule);
                sec.put(rule, p[0] + "/" + p[1] + " scenarios met their security expectation");
            }
            r.put("security_expectations", sec);
            if (a.getInt("repeat-best", 0) > 0) {
                Map<String, Object> rep = new LinkedHashMap<>();
                for (String rule : RULES) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("outcomes", genuineOutcomes.get(rule));
                    m.put("t_bind_total", bindLatency.get(rule).summary());
                    rep.put(rule, m);
                }
                Collections.sort(padOnGenuineCapture);
                rep.put("pad_on_genuine_capture_min_median_max", padOnGenuineCapture.isEmpty() ? "n/a"
                        : String.format("%.3f / %.3f / %.3f", padOnGenuineCapture.get(0),
                        padOnGenuineCapture.get(padOnGenuineCapture.size() / 2), padOnGenuineCapture.get(padOnGenuineCapture.size() - 1)));
                r.put("repeated_genuine_binds", rep);
            }
            r.put("models", models.versions);
        }
        return r;
    }

    private static CaptureBinder.SessionContext ctx(String txn, String serial, JsonNode digitalId, Instant start, List<float[]> embs) {
        return new CaptureBinder.SessionContext(txn, serial, digitalId.path("make").asText(null),
                digitalId.path("model").asText(null), start, embs);
    }

    private static Map<String, Object> entry(String scenario, Map<String, CaptureBinder> binders, byte[] resp,
                                             CaptureBinder.SessionContext ctx, Map<String, int[]> securityPass) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("scenario", scenario);
        List<String> expected = EXPECTED.get(scenario);
        if (expected != null) {
            m.put("expected", expected);
        }
        StringBuilder line = new StringBuilder(scenario);
        for (String rule : RULES) {
            BindingResult b = binders.get(rule).bind(resp, ctx, Instant.now());
            Map<String, Object> res = Phase0Cli.bindingMap(b);
            if (expected != null) {
                boolean ok = expected.contains(b.outcome + "/" + b.reason)
                        && (scenario.equals(GENUINE) || b.outcome != BindingResult.Outcome.BOUND);
                res.put("result", ok ? "PASS" : "FAIL");
                int[] p = securityPass.get(rule);
                p[1]++;
                if (ok) {
                    p[0]++;
                }
            }
            m.put(rule, res);
            line.append(" | ").append(rule).append(": ").append(b);
        }
        System.err.println(line);
        return m;
    }
}
