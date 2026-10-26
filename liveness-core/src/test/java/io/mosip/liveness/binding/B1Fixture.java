package io.mosip.liveness.binding;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.liveness.streamauth.StreamDigest;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Builds B1 prototype statements and RCAPTURE responses carrying them, signed with the TEST-ONLY keys. A "device" view:
 * the list of frames it emitted (bytes) and their device times. [CODE] fixture.
 */
public final class B1Fixture {
    public String streamId = "device-stream-" + Long.toHexString(new java.util.Random().nextLong());
    public String txn;
    public String serial = CaptureBinderTest.SERIAL;
    public Instant issuedAt = Instant.now();
    public final List<byte[]> sent = new ArrayList<>();
    public final List<Long> times = new ArrayList<>();
    public PrivateKey key = CaptureBinderTest.deviceKey;
    public X509Certificate[] chain;
    public Consumer<ObjectNode> editPayload = p -> { };
    public boolean tamper;
    public String captureDataOverride;   // hash a different capture than the one in the response
    public boolean topLevelCarrier;      // place the statement where prototype v0 put it (top-level field)

    public B1Fixture(String txn) {
        this.txn = txn;
        this.chain = new X509Certificate[] {CaptureBinderTest.deviceCert, CaptureBinderTest.caCert};
    }

    public void emit(byte[] frame, long deviceTimeMillis) {
        sent.add(frame);
        times.add(deviceTimeMillis);
    }

    public static byte[] frameBytes(long i) {
        return ("phase0-test-frame-" + i).getBytes(StandardCharsets.US_ASCII);
    }

    ObjectNode payload(String captureData) {
        ObjectNode p = CaptureBinderTest.JSON.createObjectNode().put("typ", StreamDigest.TYPE).put("streamId", streamId)
                .put("transactionId", txn).put("deviceSerial", serial)
                .put("captureDataSha256", StreamDigest.b64u(StreamDigest.sha256(
                        (captureDataOverride != null ? captureDataOverride : captureData).getBytes(StandardCharsets.US_ASCII))))
                .put("issuedAt", issuedAt.toString());
        ArrayNode fr = p.putArray("frames");
        byte[] h = StreamDigest.chainSeed(streamId, serial);
        for (int i = 0; i < sent.size(); i++) {
            byte[] fh = StreamDigest.sha256(sent.get(i));
            fr.addArray().add(i).add(times.get(i)).add(StreamDigest.b64u(fh));
            h = StreamDigest.chainStep(h, i, times.get(i), fh);
        }
        p.put("chainHead", StreamDigest.b64u(h));
        editPayload.accept(p);
        return p;
    }

    /** Adds the signed statement to an RCAPTURE response, in biometrics[0].additionalInfo (draft carrier). */
    public byte[] attach(byte[] rcaptureResponse) throws Exception {
        ObjectNode root = (ObjectNode) CaptureBinderTest.JSON.readTree(rcaptureResponse);
        String data = root.path("biometrics").path(0).path("data").asText();
        String jws = CaptureBinderTest.jws(payload(data), key, chain);
        if (tamper) {
            String[] parts = jws.split("\\.");
            ObjectNode p = payload(data);
            p.put("issuedAt", issuedAt.plusMillis(1).toString());
            jws = parts[0] + "." + CaptureBinderTest.b64u(CaptureBinderTest.JSON.writeValueAsBytes(p)) + "." + parts[2];
        }
        if (topLevelCarrier) {
            root.put("x-phase0-streamDigest", jws);
        } else {
            ((ObjectNode) root.path("biometrics").path(0)).putObject("additionalInfo").put(StreamDigest.ADDITIONAL_INFO_KEY, jws);
        }
        return CaptureBinderTest.JSON.writeValueAsBytes(root);
    }

    static JsonNode parse(byte[] b) throws Exception {
        return CaptureBinderTest.JSON.readTree(b);
    }
}
