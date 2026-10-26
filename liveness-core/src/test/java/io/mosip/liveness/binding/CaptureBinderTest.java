package io.mosip.liveness.binding;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.binding.BindingResult.Reason;
import io.mosip.liveness.sbi.JwsVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Unit tests for every binding check, using real RS256 signatures from the mock device's test-only keys and a stub
 * analyzer (so vision is not under test here). Invariant under test: no input other than a fully valid, fresh,
 * same-device, same-subject, live-looking capture yields BOUND.
 */
class CaptureBinderTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static PrivateKey deviceKey, rogueKey;
    static X509Certificate deviceCert, caCert, rogueCert;
    static JwsVerifier verifier;
    static byte[] isoJpeg;

    static final String SERIAL = "PHASE0-MOCK-FACE-0001";
    static final float[] SUBJECT = unit(1f, 0f);
    static final float[] OTHER = unit(0f, 1f);

    @BeforeAll
    static void keys() throws Exception {
        deviceKey = key("/keys/device.key");
        rogueKey = key("/keys/rogue.key");
        deviceCert = cert("/keys/device.pem");
        caCert = cert("/keys/ca.pem");
        rogueCert = cert("/keys/rogue.pem");
        verifier = new JwsVerifier(Collections.singletonList(caCert));
        BufferedImage img = new BufferedImage(40, 50, BufferedImage.TYPE_3BYTE_BGR);
        ByteArrayOutputStream jpg = new ByteArrayOutputStream();
        ImageIO.write(img, "jpeg", jpg);
        isoJpeg = iso(jpg.toByteArray(), 40, 50, 0);
    }

    // ------------------------------------------------------------------ fixtures
    static float[] unit(float a, float b) {
        float[] v = new float[128];
        v[0] = a;
        v[1] = b;
        return v;
    }

    static PrivateKey key(String res) throws Exception {
        String pem = new String(read(res), StandardCharsets.US_ASCII).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
    }

    static X509Certificate cert(String res) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(read(res)));
    }

    static byte[] read(String res) throws Exception {
        try (InputStream in = CaptureBinderTest.class.getResourceAsStream(res)) {
            return in.readAllBytes();
        }
    }

    static String b64u(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String jws(ObjectNode payload, PrivateKey k, X509Certificate... chain) throws Exception {
        ObjectNode h = JSON.createObjectNode().put("alg", "RS256").put("typ", "JWT");
        for (X509Certificate c : chain) {
            h.withArray("x5c").add(Base64.getEncoder().encodeToString(c.getEncoded()));
        }
        String si = b64u(JSON.writeValueAsBytes(h)) + "." + b64u(JSON.writeValueAsBytes(payload));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(k);
        s.update(si.getBytes(StandardCharsets.US_ASCII));
        return si + "." + b64u(s.sign());
    }

    /** ISO/IEC 19794-5 record in the same layout as tools/mock-sbi (validated against MOSIP Face.iso). */
    static byte[] iso(byte[] img, int w, int h, int type) {
        ByteBuffer rep = ByteBuffer.allocate(1024 + img.length);
        rep.putShort((short) 2026).put(new byte[] {10, 23, 3, 0, 0}).putShort((short) 0);
        rep.put((byte) 5).putShort((short) 0).putShort((short) 0);
        rep.put((byte) 1).put((byte) 80).putShort((short) 1).putShort((short) 1);
        rep.putShort((short) 0);
        rep.put(new byte[15]);
        rep.put((byte) 1).put((byte) type).putShort((short) w).putShort((short) h);
        rep.put(new byte[] {0, 0, 1, 0, 1});
        rep.putInt(img.length).put(img);
        int repLen = 4 + rep.position();
        ByteBuffer out = ByteBuffer.allocate(17 + repLen);
        out.put(new byte[] {'F', 'A', 'C', 0, '0', '3', '0', 0}).putInt(17 + repLen).putShort((short) 1).put((byte) 0).putShort((short) 0);
        out.putInt(repLen).put(rep.array(), 0, rep.position());
        return out.array();
    }

    static final class Capture {
        String txn = "txn-1";
        Instant ts = Instant.now();
        String serial = SERIAL;
        String bioType = "Face";
        byte[] bioValue = isoJpeg;
        String errorCode = "0";
        PrivateKey dataKey = deviceKey;
        X509Certificate[] dataChain = {deviceCert, caCert};
        PrivateKey idKey = deviceKey;
        X509Certificate[] idChain = {deviceCert, caCert};
        boolean omitTxn;
        boolean tamper;
        String rawTimestamp;      // overrides ts verbatim (format tests)
    }

    static byte[] response(Consumer<Capture> edit) throws Exception {
        Capture c = new Capture();
        edit.accept(c);
        ObjectNode id = JSON.createObjectNode().put("serialNo", c.serial).put("make", "Phase0").put("model", "MOCK-FACE-1")
                .put("type", "Face").put("dateTime", Instant.now().toString());
        ObjectNode p = JSON.createObjectNode().put("digitalId", jws(id, c.idKey, c.idChain)).put("bioType", c.bioType)
                .put("bioSubType", "").put("purpose", "Registration").put("env", "Developer")
                .put("bioValue", b64u(c.bioValue)).put("timestamp", c.rawTimestamp != null ? c.rawTimestamp : c.ts.toString()).put("qualityScore", "80");
        if (!c.omitTxn) {
            p.put("transactionId", c.txn);
        }
        String data = jws(p, c.dataKey, c.dataChain);
        if (c.tamper) {
            String[] parts = data.split("\\.");
            p.put("qualityScore", "99");
            data = parts[0] + "." + b64u(JSON.writeValueAsBytes(p)) + "." + parts[2];
        }
        ObjectNode bio = JSON.createObjectNode().put("specVersion", "0.9.5").put("data", data).put("hash", "x");
        bio.putObject("error").put("errorCode", c.errorCode).put("errorInfo", "");
        ObjectNode root = JSON.createObjectNode();
        root.putArray("biometrics").add(bio);
        return JSON.writeValueAsBytes(root);
    }

    static byte[] responseWithRawTimestamp(String txn, String timestamp) throws Exception {
        return response(c -> { c.txn = txn; c.rawTimestamp = timestamp; });
    }

    static CaptureAnalyzer stub(int faces, Float pad, float[] emb) {
        return image -> new CaptureAnalyzer.Analysis(faces, pad, emb);
    }

    static CaptureBinder binder(CaptureAnalyzer a) {
        return new CaptureBinder(verifier, verifier, a, new CaptureBinder.Policy());
    }

    static CaptureBinder.SessionContext ctx(int nEmb) {
        List<float[]> e = new ArrayList<>();
        for (int i = 0; i < nEmb; i++) {
            e.add(SUBJECT);
        }
        return new CaptureBinder.SessionContext("txn-1", SERIAL, "Phase0", "MOCK-FACE-1", Instant.now().minusSeconds(10), e);
    }

    static BindingResult bind(Consumer<Capture> edit, CaptureAnalyzer a) throws Exception {
        return binder(a).bind(response(edit), ctx(5), Instant.now());
    }

    static final CaptureAnalyzer GOOD = stub(1, 0.95f, SUBJECT);

    static void expect(BindingResult r, Outcome o, Reason why) {
        assertEquals(o + "/" + why, r.outcome + "/" + r.reason, r.toString());
    }

    // ------------------------------------------------------------------ tests
    @Test
    void validCaptureBinds() throws Exception {
        BindingResult r = bind(c -> { }, GOOD);
        expect(r, Outcome.BOUND, Reason.OK);
        assertEquals(64, r.signedDataSha256.length());
    }

    @Test
    void tamperedPayloadFailsSignature() throws Exception {
        expect(bind(c -> c.tamper = true, GOOD), Outcome.REJECTED, Reason.BAD_SIGNATURE);
    }

    @Test
    void signerNotChainedToTrustAnchorIsUntrusted() throws Exception {
        expect(bind(c -> { c.dataKey = rogueKey; c.dataChain = new X509Certificate[] {rogueCert}; }, GOOD),
                Outcome.REJECTED, Reason.UNTRUSTED_DEVICE);
    }

    @Test
    void untrustedDigitalIdIsRejected() throws Exception {
        expect(bind(c -> { c.idKey = rogueKey; c.idChain = new X509Certificate[] {rogueCert}; }, GOOD),
                Outcome.REJECTED, Reason.DIGITAL_ID_INVALID);
    }

    @Test
    void transactionIdMustEchoTheRequestNonce() throws Exception {
        expect(bind(c -> c.txn = "someone-elses-txn", GOOD), Outcome.REJECTED, Reason.TRANSACTION_MISMATCH);
        // owner decision 2026-10-24: an absent nonce on an authenticated same-device response is distinguished
        expect(bind(c -> c.omitTxn = true, GOOD), Outcome.REJECTED, Reason.TRANSACTION_ABSENT);
    }

    @Test
    void captureOlderThanSessionIsStaleAndFutureIsRejected() throws Exception {
        expect(bind(c -> c.ts = Instant.now().minus(Duration.ofMinutes(15)), GOOD), Outcome.REJECTED, Reason.CAPTURE_STALE);
        expect(bind(c -> c.ts = Instant.now().plus(Duration.ofMinutes(15)), GOOD), Outcome.REJECTED, Reason.CAPTURE_FROM_FUTURE);
    }

    @Test
    void captureFromAnotherDeviceIsRejected() throws Exception {
        expect(bind(c -> c.serial = "OTHER-DEVICE", GOOD), Outcome.REJECTED, Reason.DEVICE_MISMATCH);
    }

    @Test
    void byteIdenticalReplayIsRejectedEvenWithMatchingNonce() throws Exception {
        CaptureBinder b = binder(GOOD);
        byte[] resp = response(c -> { });
        expect(b.bind(resp, ctx(5), Instant.now()), Outcome.BOUND, Reason.OK);
        expect(b.bind(resp, ctx(5), Instant.now()), Outcome.REJECTED, Reason.REPLAYED_RESPONSE);
    }

    @Test
    void deviceErrorAndMalformedResponsesAreRejected() throws Exception {
        expect(bind(c -> c.errorCode = "701", GOOD), Outcome.REJECTED, Reason.DEVICE_ERROR);
        expect(binder(GOOD).bind("not json".getBytes(StandardCharsets.UTF_8), ctx(5), Instant.now()),
                Outcome.REJECTED, Reason.MALFORMED_RESPONSE);
        expect(binder(GOOD).bind("{\"biometrics\":[]}".getBytes(StandardCharsets.UTF_8), ctx(5), Instant.now()),
                Outcome.REJECTED, Reason.MALFORMED_RESPONSE);
    }

    @Test
    void nonFaceOrUndecodableBioValueIsRejected() throws Exception {
        expect(bind(c -> c.bioType = "Finger", GOOD), Outcome.REJECTED, Reason.BAD_BIO_FORMAT);
        expect(bind(c -> c.bioValue = Arrays.copyOf(isoJpeg, isoJpeg.length - 3), GOOD), Outcome.REJECTED, Reason.BAD_BIO_FORMAT);
        expect(bind(c -> c.bioValue = iso(new byte[] {1, 2, 3, 4}, 40, 50, 0), GOOD), Outcome.REJECTED, Reason.BAD_BIO_FORMAT);
    }

    @Test
    void headerImageSizeMustMatchDecodedImage() throws Exception {
        byte[] jpg = Arrays.copyOfRange(isoJpeg, isoJpeg.length - jpegLength(), isoJpeg.length);
        expect(bind(c -> c.bioValue = iso(jpg, 400, 500, 0), GOOD), Outcome.REJECTED, Reason.BAD_BIO_FORMAT);
    }

    private static int jpegLength() {
        ByteBuffer b = ByteBuffer.wrap(isoJpeg);
        return b.getInt(69);
    }

    @Test
    void faceCountMustBeExactlyOne() throws Exception {
        expect(bind(c -> { }, stub(0, null, null)), Outcome.REJECTED, Reason.NO_FACE);
        expect(bind(c -> { }, stub(2, null, null)), Outcome.REJECTED, Reason.MULTIPLE_FACES);
    }

    @Test
    void defaultIsTheConservativeAcceptGate() throws Exception {
        expect(bind(c -> { }, stub(1, 0.05f, SUBJECT)), Outcome.ATTACK, Reason.PAD_ATTACK);
        expect(bind(c -> { }, stub(1, 0.50f, SUBJECT)), Outcome.UNCERTAIN, Reason.PAD_UNCERTAIN);
        expect(bind(c -> { }, stub(1, 0.85f, SUBJECT)), Outcome.BOUND, Reason.OK);
    }

    @Test
    void proposedVetoOnlyRuleMustBeSelectedExplicitly() throws Exception {
        CaptureBinder b = new CaptureBinder(verifier, verifier, stub(1, 0.50f, SUBJECT), CaptureBinder.Policy.proposedVetoOnly());
        expect(b.bind(response(c -> { }), ctx(5), Instant.now()), Outcome.BOUND, Reason.OK);
        CaptureBinder v = new CaptureBinder(verifier, verifier, stub(1, 0.05f, SUBJECT), CaptureBinder.Policy.proposedVetoOnly());
        expect(v.bind(response(c -> { }), ctx(5), Instant.now()), Outcome.ATTACK, Reason.PAD_ATTACK);
    }

    @Test
    void attackVerdictWinsOverSubjectMismatch() throws Exception {
        expect(bind(c -> { }, stub(1, 0.05f, OTHER)), Outcome.ATTACK, Reason.PAD_ATTACK);
    }

    @Test
    void differentSubjectIsRejected() throws Exception {
        expect(bind(c -> { }, stub(1, 0.95f, OTHER)), Outcome.REJECTED, Reason.SUBJECT_MISMATCH);
    }

    @Test
    void tooLittleStreamEvidenceIsNeverBound() throws Exception {
        BindingResult r = binder(GOOD).bind(response(c -> { }), ctx(2), Instant.now());
        expect(r, Outcome.UNCERTAIN, Reason.INSUFFICIENT_STREAM_EVIDENCE);
    }

    @Test
    void analyzerFailuresAndInvalidOutputsFailClosed() throws Exception {
        CaptureAnalyzer throwing = image -> { throw new IllegalStateException("ORT failed"); };
        expect(bind(c -> { }, throwing), Outcome.ERROR, Reason.ENGINE_ERROR);
        expect(bind(c -> { }, stub(1, Float.NaN, SUBJECT)), Outcome.ERROR, Reason.ENGINE_ERROR);
        expect(bind(c -> { }, stub(1, null, SUBJECT)), Outcome.ERROR, Reason.ENGINE_ERROR);
        expect(bind(c -> { }, stub(1, 0.95f, null)), Outcome.ERROR, Reason.ENGINE_ERROR);
        float[] nanEmb = unit(Float.NaN, 0f);
        assertNotEquals(Outcome.BOUND, bind(c -> { }, stub(1, 0.95f, nanEmb)).outcome);
    }

    @Test
    void timestampParsingAcceptsSbiFormatsAndRejectsGarbage() {
        assertEquals(Instant.parse("2026-10-22T21:51:45.928Z"), CaptureBinder.parseTimestamp("2026-10-22T21:51:45.928Z"));
        assertEquals(Instant.parse("2026-10-22T21:51:45Z"), CaptureBinder.parseTimestamp("2026-10-23T03:21:45+05:30"));
        assertEquals(null, CaptureBinder.parseTimestamp("23/10/2026"));
    }
}
