package io.mosip.liveness.vision;

import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Creates ONNX Runtime sessions with explicit, latency-oriented settings and integrity-checks model files.
 *
 * <p>Sessions are created once and reused for the process lifetime (model load is never on the critical path).
 * Thread count is explicit because the Registration Client shares the CPU with JavaFX, the stream reader and
 * packet crypto; the right value is a benchmark result, not a default.
 */
public final class OrtModels {
    private OrtModels() {}

    private static volatile boolean telemetryDisabled;

    /**
     * The process-wide ORT environment with ORT's own telemetry <b>disabled</b>.
     *
     * <p>Phase-0 finding R12: the macOS/Linux ORT 1.30 natives embed Microsoft's 1DS telemetry client (collector
     * {@code mobile.events.data.microsoft.com}); its HTTP worker thread racing teardown at JVM exit was the cause of the
     * "recursive_mutex lock failed" aborts. A biometric client must not make undeclared network calls from its
     * inference library. Set {@code -Dliveness.ortTelemetry=true} only for experiments that measure this behaviour.
     *
     * <p><b>This call is necessary but not sufficient:</b> ORT documents that the API suppresses only non-essential
     * telemetry, and with it alone 1 in 24 test exits still aborted. The launcher must also export
     * {@code ORT_DISABLE_TELEMETRY=1} before the JVM starts (0 aborts observed), or ORT must be built with
     * {@code --no_telemetry} (production requirement).
     */
    public static OrtEnvironment env() {
        OrtEnvironment e = OrtEnvironment.getEnvironment();
        if (!telemetryDisabled && !Boolean.getBoolean("liveness.ortTelemetry")) {
            synchronized (OrtModels.class) {
                if (!telemetryDisabled) {
                    try {
                        e.setTelemetry(false);
                    } catch (ai.onnxruntime.OrtException ex) {
                        throw new IllegalStateException("could not disable ONNX Runtime telemetry; refusing to continue", ex);
                    }
                    telemetryDisabled = true;
                }
            }
        }
        return e;
    }

    public static OrtSession open(Path model, int intraOpThreads, String expectedSha256) throws OrtException, IOException {
        if (expectedSha256 != null) {
            String actual = sha256(model);
            if (!actual.equalsIgnoreCase(expectedSha256)) {
                // Fail closed: a modified model must never be loaded (invariant I8 / T11).
                throw new IOException("model integrity check failed for " + model.getFileName() + ": " + actual);
            }
        }
        OrtSession.SessionOptions so = new OrtSession.SessionOptions();
        so.setIntraOpNumThreads(intraOpThreads);
        so.setInterOpNumThreads(1);
        so.setExecutionMode(OrtSession.SessionOptions.ExecutionMode.SEQUENTIAL);
        so.setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT);
        so.setSessionLogLevel(ai.onnxruntime.OrtLoggingLevel.ORT_LOGGING_LEVEL_ERROR);
        try {
            return env().createSession(model.toString(), so);
        } finally {
            so.close(); // native options object; the session keeps its own copy
        }
    }

    public static String sha256(Path p) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(Files.readAllBytes(p));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
