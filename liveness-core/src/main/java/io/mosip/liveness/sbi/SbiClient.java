package io.mosip.liveness.sbi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;

/**
 * Minimal SBI 1.0 client (desktop/HTTP binding). Uses the SBI custom verbs exactly as the Registration Client
 * does ({@code MOSIPDISC}, {@code MOSIPDINFO}, {@code STREAM}, {@code RCAPTURE}) against {@code 127.0.0.1}.
 */
public final class SbiClient {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RNG = new SecureRandom();

    private final String host;
    private final int port;
    private final HttpClient http;

    public SbiClient(int port) {
        this("127.0.0.1", port);
    }

    public SbiClient(String host, int port) {
        this.host = host;
        this.port = port;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .version(HttpClient.Version.HTTP_1_1).build();
    }

    public int port() { return port; }

    public JsonNode discover() throws IOException, InterruptedException {
        ObjectNode body = JSON.createObjectNode().put("type", "Biometric Device");
        return JSON.readTree(send("MOSIPDISC", "device", body, Duration.ofSeconds(5)));
    }

    public JsonNode info() throws IOException, InterruptedException {
        return JSON.readTree(send("MOSIPDINFO", "info", JSON.createObjectNode(), Duration.ofSeconds(5)));
    }

    /** Opens the face STREAM; the caller owns (and must close) the returned body stream. */
    public InputStream openStream(String serialNo, String deviceSubId, long timeoutMs) throws IOException, InterruptedException {
        ObjectNode body = JSON.createObjectNode().put("serialNo", serialNo).put("deviceSubId", deviceSubId)
                .put("timeout", Long.toString(timeoutMs));
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://" + host + ":" + port + "/stream"))
                .method("STREAM", HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build();
        HttpResponse<InputStream> resp = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
        if (resp.statusCode() != 200) {
            resp.body().close();
            throw new IOException("STREAM returned HTTP " + resp.statusCode());
        }
        return resp.body();
    }

    /** A fresh, unpredictable transaction id; it is the nonce that binds an RCAPTURE response to this request. */
    public static String newTransactionId() {
        return new UUID(RNG.nextLong(), RNG.nextLong()).toString();
    }

    /** Issues a face RCAPTURE and returns the raw response body (verification happens in the binder). */
    public byte[] rcaptureFace(String transactionId, String env, String purpose, long timeoutMs, long captureTimeMs,
                               JsonNode customOpts) throws IOException, InterruptedException {
        ObjectNode body = JSON.createObjectNode().put("env", env).put("purpose", purpose).put("specVersion", "0.9.5")
                .put("timeout", Long.toString(timeoutMs)).put("captureTime", Long.toString(captureTimeMs))
                .put("domainUri", "http://127.0.0.1").put("transactionId", transactionId);
        ObjectNode bio = body.putArray("bio").addObject();
        bio.put("type", "Face").put("count", "1").put("deviceSubId", "0").put("requestedScore", "40")
                .put("deviceId", "1").putArray("bioSubType");
        bio.putArray("exception");
        if (customOpts != null) {
            body.set("customOpts", customOpts);
        }
        return send("RCAPTURE", "capture", body, Duration.ofMillis(timeoutMs + 5000));
    }

    /**
     * Face RCAPTURE shaped like the desktop Registration Client's SBI 1.0 request
     * ({@code MosipDeviceSpecification_SBI_1_0_ProviderImpl.getRCaptureRequest}, develop @ e9ff40b): device specVersion,
     * ISO {@code captureTime}, bio.serialNo, bio.previousHash = SHA-256("") (upper-case hex), no bio.deviceId, nulls kept.
     * Used by the real-device probe so a device sees what the client would send.
     */
    public byte[] rcaptureFaceSbi10(String transactionId, String env, String purpose, String specVersion, String serialNo,
                                    long timeoutMs) throws IOException, InterruptedException {
        ObjectNode body = JSON.createObjectNode().put("env", env).put("purpose", purpose).put("specVersion", specVersion)
                .put("timeout", Long.toString(timeoutMs))
                .put("captureTime", java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME))
                .put("transactionId", transactionId).putNull("domainUri");
        ObjectNode bio = body.putArray("bio").addObject();
        bio.put("type", "Face").put("count", "1").putNull("exception").put("requestedScore", "40").put("serialNo", serialNo)
                .putNull("bioSubType").put("deviceSubId", "0").put("previousHash", emptySha256Hex());
        body.putNull("customOpts");
        return send("RCAPTURE", "capture", body, Duration.ofMillis(timeoutMs + 5000));
    }

    static String emptySha256Hex() {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest(new byte[0]);
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] send(String verb, String path, JsonNode body, Duration timeout) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://" + host + ":" + port + "/" + path))
                .timeout(timeout)
                .method(verb, HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build();
        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() != 200) {
            throw new IOException(verb + " returned HTTP " + resp.statusCode());
        }
        return resp.body();
    }
}
