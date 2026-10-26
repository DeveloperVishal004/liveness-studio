package io.mosip.liveness.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.binding.VisionCaptureAnalyzer;
import io.mosip.liveness.frame.EncodedFrame;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.pipeline.LatencyStats;
import io.mosip.liveness.pipeline.LiveStreamRun;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.sbi.SbiClient;
import io.mosip.liveness.vision.Phase0Models;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Phase-0 command line.
 * <pre>
 *   probe          --port P [--seconds 20] [--trust pem] [--no-capture] [--flash] [--out file]
 *   bench-replay   --images f1 [f2 ...] [--frames 2000] [--threads 2] [--int8] [--out file]
 *   bench-live     --port P [--seconds 30] [--threads 2] [--detect-every 1] [--int8] [--out file]
 *   bind-scenarios --port P --trust pem [--out file]
 *   session-scenarios --port P --trust pem [--scenarios a,b] [--stream-kind live|static] [--out file]
 * common: --root &lt;repo root&gt; (default: ..), --det-width 320
 * </pre>
 * Reports never contain images or embeddings.
 */
public final class Phase0Cli {
    static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String[] argv) throws Exception {
        if (argv.length == 0) {
            System.err.println("usage: probe | bench-replay | bench-live | bind-scenarios | session-scenarios  (see class javadoc)");
            System.exit(2);
        }
        Args a = new Args(Arrays.copyOfRange(argv, 1, argv.length));
        startBackgroundLoad(a.getInt("background-load", 0));
        Map<String, Object> report;
        switch (argv[0]) {
            case "probe": report = SbiProbe.run(a); break;
            case "bench-replay": report = benchReplay(a); break;
            case "bench-live": report = benchLive(a); break;
            case "bind-scenarios": report = BindScenarios.run(a); break;
            case "session-scenarios": report = SessionScenarios.run(a); break;
            case "webcam-live": report = WebcamLive.run(a); break;
            default: throw new IllegalArgumentException("unknown command " + argv[0]);
        }
        report.put("environment", environment(a));
        String out = JSON.writeValueAsString(report);
        if (a.has("out")) {
            Files.createDirectories(Paths.get(a.get("out")).toAbsolutePath().getParent());
            Files.write(Paths.get(a.get("out")), out.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            System.err.println("report written to " + a.get("out"));
        }
        System.out.println(out);
        System.out.flush();
        if (!a.has("no-env-close")) {
            // All sessions are closed by now; release the native environment before JVM exit (R8 hypothesis:
            // ORT static teardown racing at exit while the environment is still open).
            ai.onnxruntime.OrtEnvironment.getEnvironment().close();
        }
        System.exit(0);
    }

    /**
     * Synthetic co-tenant CPU load (stands in for packet encryption / JavaFX / BioSDK work on a registration client):
     * N daemon threads hashing 1 MB buffers continuously.
     */
    static void startBackgroundLoad(int threads) {
        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                    byte[] buf = new byte[1 << 20];
                    long sink = 0;
                    while (true) {
                        sink += md.digest(buf)[0];
                        buf[(int) (sink & 0xFFFFF)]++;
                    }
                } catch (java.security.NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            }, "phase0-background-load-" + i);
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY);
            t.start();
        }
    }

    static Phase0Models models(Args a) throws Exception {
        return Phase0Models.load(Paths.get(a.get("root", "..")), a.getInt("threads", 2), a.getInt("det-width", 320),
                a.has("int8"));
    }

    static FramePipeline.Config pipelineConfig(Args a) {
        FramePipeline.Config c = new FramePipeline.Config();
        c.detectEvery = a.getInt("detect-every", 1);
        c.embedEvery = a.getInt("embed-every", 5);
        c.asyncEmbedding = !a.has("inline-embed");
        return c;
    }

    /** Offline per-stage benchmark: same pipeline, frames fed back-to-back (no device, no mailbox). */
    static Map<String, Object> benchReplay(Args a) throws Exception {
        List<byte[]> imgs = new ArrayList<>();
        for (String p : a.getList("images")) {
            Path path = Paths.get(p);
            if (Files.isDirectory(path)) {
                try (Stream<Path> s = Files.list(path)) {
                    for (Path f : s.filter(x -> x.toString().toLowerCase().matches(".*\\.jpe?g")).sorted().collect(Collectors.toList())) {
                        imgs.add(Files.readAllBytes(f));
                    }
                }
            } else {
                imgs.add(Files.readAllBytes(path));
            }
        }
        if (imgs.isEmpty()) {
            throw new IllegalArgumentException("--images found no JPEG files");
        }
        int frames = a.getInt("frames", 2000);
        int warmup = a.getInt("warmup", 100);
        long tLoad = System.nanoTime();
        Map<String, Object> r = new LinkedHashMap<>();
        try (Phase0Models m = models(a)) {
            double loadMs = (System.nanoTime() - tLoad) / 1e6;
            FramePipeline pipe = new FramePipeline(m, pipelineConfig(a));
            long tw = System.nanoTime();
            pipe.process(new EncodedFrame(0, System.nanoTime(), 0, "image/jpeg", imgs.get(0)));
            double firstMs = (System.nanoTime() - tw) / 1e6;
            for (int i = 0; i < warmup; i++) {
                pipe.process(new EncodedFrame(i, System.nanoTime(), 0, "image/jpeg", imgs.get(i % imgs.size())));
            }
            Map<String, LatencyStats> spans = new LinkedHashMap<>();
            LatencyStats total = new LatencyStats();
            int eligible = 0;
            for (int i = 0; i < frames; i++) {
                long t0 = System.nanoTime();
                FramePipeline.FrameEvidence ev = pipe.process(new EncodedFrame(i, t0, 0, "image/jpeg", imgs.get(i % imgs.size())));
                total.record(System.nanoTime() - t0);
                if (ev.eligible) {
                    eligible++;
                }
                for (Map.Entry<String, Long> e : ev.spans.entrySet()) {
                    spans.computeIfAbsent(e.getKey(), k -> new LatencyStats()).record(e.getValue());
                }
            }
            r.put("models", m.versions);
            r.put("cold_start_load_ms", Math.round(loadMs));
            r.put("first_frame_ms", Math.round(firstMs));
            r.put("images", imgs.size());
            r.put("frames", frames);
            r.put("eligible_frames", eligible);
            r.put("t_passive_frame", total.summary());
            Map<String, Object> st = new LinkedHashMap<>();
            spans.forEach((k, v) -> st.put(k, v.summary()));
            r.put("stages", st);
            r.put("config", configMap(a));
            pipe.close(); // joins the embedding sampler before the sessions close (R10)
        }
        return r;
    }

    /** Live benchmark against an SBI stream with the production threading model. */
    static Map<String, Object> benchLive(Args a) throws Exception {
        SbiClient sbi = new SbiClient(a.getInt("port", 4501));
        Map<String, Object> r = new LinkedHashMap<>();
        try (Phase0Models m = models(a)) {
            FramePipeline pipe = new FramePipeline(m, pipelineConfig(a));
            String serial = SbiProbe.deviceSerial(sbi.info());
            InputStream s = sbi.openStream(serial, "0", a.getLong("seconds", 30) * 1000 + 10000);
            // The first processed frames (ORT kernel selection, JIT) are excluded from latency statistics.
            LiveStreamRun run = new LiveStreamRun(s, pipe, a.getLong("seconds", 30) * 1000, a.getInt("warmup-frames", 10));
            run.run();
            pipe.close(); // joins the embedding sampler before the sessions close (R10)
            r.put("models", m.versions);
            r.putAll(run.report());
            r.put("config", configMap(a));
        }
        return r;
    }

    static Map<String, Object> configMap(Args a) {
        Map<String, Object> c = new LinkedHashMap<>(a.map);
        c.putIfAbsent("threads", "2");
        c.putIfAbsent("det-width", "320");
        c.putIfAbsent("detect-every", "1");
        return c;
    }

    static Map<String, Object> environment(Args a) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("timestamp", Instant.now().toString());
        e.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version") + " " + System.getProperty("os.arch"));
        e.put("java", System.getProperty("java.vendor") + " " + System.getProperty("java.version"));
        e.put("available_processors", Runtime.getRuntime().availableProcessors());
        e.put("max_heap_mb", Runtime.getRuntime().maxMemory() / (1024 * 1024));
        e.put("cpu", cpuName());
        e.put("ORT_DISABLE_TELEMETRY", String.valueOf(System.getenv("ORT_DISABLE_TELEMETRY")));
        e.put("ort_api_telemetry_disabled", !Boolean.getBoolean("liveness.ortTelemetry"));
        e.put("evidence_class", "Host machine as recorded above; device class depends on the SBI endpoint (mock vs real) - see docs/phase0/EVIDENCE_INDEX.md");
        try {
            e.put("onnxruntime", ai.onnxruntime.OrtEnvironment.getEnvironment().getVersion());
        } catch (Throwable t) {
            e.put("onnxruntime", "unavailable: " + t);
        }
        return e;
    }

    /** Best-effort CPU model string (Windows: PROCESSOR_IDENTIFIER; macOS: sysctl; Linux: /proc/cpuinfo). */
    static String cpuName() {
        String w = System.getenv("PROCESSOR_IDENTIFIER");
        if (w != null) {
            return w;
        }
        try {
            java.nio.file.Path ci = java.nio.file.Paths.get("/proc/cpuinfo");
            if (java.nio.file.Files.isReadable(ci)) {
                for (String l : java.nio.file.Files.readAllLines(ci)) {
                    if (l.startsWith("model name")) {
                        return l.substring(l.indexOf(':') + 1).trim();
                    }
                }
            }
            Process p = new ProcessBuilder("sysctl", "-n", "machdep.cpu.brand_string").redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor();
            return out.isEmpty() ? "unknown" : out;
        } catch (Exception e) {
            return "unknown";
        }
    }

    static CaptureBinder binder(Path trust, Phase0Models models) throws Exception {
        JwsVerifier v = JwsVerifier.fromPem(trust);
        return new CaptureBinder(v, v, new VisionCaptureAnalyzer(models), new CaptureBinder.Policy());
    }

    static Map<String, Object> bindingMap(BindingResult b) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("outcome", b.outcome.name());
        m.put("reason", b.reason.name());
        if (b.detail != null) {
            m.put("detail", b.detail);
        }
        if (b.padRealProbability != null) {
            m.put("pad_p_real", Math.round(b.padRealProbability * 1000) / 1000.0);
        }
        if (b.subjectCosine != null) {
            m.put("subject_cosine", Math.round(b.subjectCosine * 1000) / 1000.0);
        }
        m.put("bind_ms", Math.round(b.elapsedNanos / 1e5) / 10.0);
        if (b.decodeNanos > 0) {
            m.put("decode_ms", Math.round(b.decodeNanos / 1e5) / 10.0);
            m.put("analyze_ms", Math.round(b.analyzeNanos / 1e5) / 10.0);
        }
        return m;
    }

    static JsonNode verifiedOrUnverified(String jws, JwsVerifier v, Map<String, Object> note) throws IOException {
        if (v == null) {
            note.put("signature", "NOT VERIFIED (no --trust given)");
            return JwsVerifier.unverifiedPayload(jws);
        }
        try {
            JsonNode p = v.verify(jws, new Date()).payload;
            note.put("signature", "valid, chains to trust anchor");
            return p;
        } catch (JwsVerifier.JwsException e) {
            note.put("signature", "INVALID: " + e.reason);
            return JwsVerifier.unverifiedPayload(jws);
        }
    }

    static ObjectNode customMode(String mode) {
        return JSON.createObjectNode().put("phase0CaptureMode", mode);
    }

    /** Tiny argument parser: --key value, --flag, --key v1 v2 ... */
    static final class Args {
        final Map<String, String> map = new LinkedHashMap<>();
        final Map<String, List<String>> lists = new HashMap<>();

        /** Every option any subcommand understands. Unknown options are errors, never silently ignored (R14). */
        static final java.util.Set<String> KNOWN = new java.util.HashSet<>(Arrays.asList(
                "root", "threads", "det-width", "int8", "detect-every", "embed-every", "inline-embed", "out",
                "background-load", "no-env-close", "images", "frames", "warmup", "port", "seconds", "warmup-frames",
                "trust", "no-capture", "flash", "flash-cycles", "env", "purpose", "capture-timeout-ms",
                "capture-time-ms", "repeat-best", "swaps", "scenarios", "stream-kind", "window-variation", "repeat", "b1", "request-format", "crl", "headless", "trials", "serve", "ui-dir", "ui-port", "open-browser", "camera-label"));

        Args(String[] a) {
            for (int i = 0; i < a.length; i++) {
                if (!a[i].startsWith("--")) {
                    throw new IllegalArgumentException("unexpected argument " + a[i]);
                }
                String k = a[i].substring(2);
                if (!KNOWN.contains(k)) {
                    throw new IllegalArgumentException("unknown option --" + k + " (a benchmark must never run with an ignored flag)");
                }
                List<String> vals = new ArrayList<>();
                while (i + 1 < a.length && !a[i + 1].startsWith("--")) {
                    vals.add(a[++i]);
                }
                lists.put(k, vals);
                map.put(k, vals.isEmpty() ? "true" : vals.get(0));
            }
        }

        boolean has(String k) { return map.containsKey(k); }
        String get(String k) {
            if (!map.containsKey(k)) {
                throw new IllegalArgumentException("missing --" + k);
            }
            return map.get(k);
        }
        String get(String k, String d) { return map.getOrDefault(k, d); }
        int getInt(String k, int d) { return has(k) ? Integer.parseInt(map.get(k)) : d; }
        long getLong(String k, long d) { return has(k) ? Long.parseLong(map.get(k)) : d; }
        List<String> getList(String k) {
            List<String> l = lists.get(k);
            if (l == null || l.isEmpty()) {
                throw new IllegalArgumentException("missing --" + k);
            }
            return l;
        }
    }

    private Phase0Cli() {}
}
