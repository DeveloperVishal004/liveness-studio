package io.mosip.liveness.binding;

import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.sbi.JwsVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Offline CRL revocation in {@link JwsVerifier} (U6). TEST-ONLY CRLs from the mock CA: revoked (device2 revoked),
 * empty, stale (nextUpdate in the past). The real MOSIP revocation source is an open question (D-MOS-8). [CODE]
 */
class RevocationTest {
    static PrivateKey device2Key;
    static X509Certificate device2Cert;

    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
        device2Key = CaptureBinderTest.key("/keys/device2.key");
        device2Cert = CaptureBinderTest.cert("/keys/device2.pem");
    }

    static Path res(String name) throws Exception {
        return Paths.get(RevocationTest.class.getResource("/keys/" + name).toURI());
    }

    static JwsVerifier with(String... crls) throws Exception {
        List<Path> ps = new java.util.ArrayList<>();
        for (String c : crls) {
            ps.add(res(c));
        }
        return JwsVerifier.fromPem(res("ca.pem"), ps);
    }

    static String signedBy(PrivateKey k, X509Certificate leaf) throws Exception {
        return CaptureBinderTest.jws(CaptureBinderTest.JSON.createObjectNode().put("k", "v"), k, leaf, CaptureBinderTest.caCert);
    }

    static JwsVerifier.Reason reason(JwsVerifier v, String jws) {
        return assertThrows(JwsVerifier.JwsException.class, () -> v.verify(jws, new Date())).reason;
    }

    @Test
    void revokedSignerIsRejectedAndOthersUnderTheSameCaPass() throws Exception {
        JwsVerifier v = with("revoked.crl.pem");
        assertTrue(v.revocationChecked());
        assertEquals(JwsVerifier.Reason.CERT_REVOKED, reason(v, signedBy(device2Key, device2Cert)));
        v.verify(signedBy(CaptureBinderTest.deviceKey, CaptureBinderTest.deviceCert), new Date());   // not revoked: passes
    }

    @Test
    void emptyCrlAcceptsAndNoCrlKeepsThePreviousBehaviour() throws Exception {
        with("empty.crl.pem").verify(signedBy(device2Key, device2Cert), new Date());
        JwsVerifier none = JwsVerifier.fromPem(res("ca.pem"), Collections.emptyList());
        assertFalse(none.revocationChecked());
        none.verify(signedBy(device2Key, device2Cert), new Date());
    }

    @Test
    void staleCrlMeansRevocationUndeterminedAndFailsClosed() throws Exception {
        JwsVerifier v = with("stale.crl.pem");
        assertEquals(JwsVerifier.Reason.UNTRUSTED_CHAIN, reason(v, signedBy(CaptureBinderTest.deviceKey, CaptureBinderTest.deviceCert)));
        assertEquals(JwsVerifier.Reason.UNTRUSTED_CHAIN, reason(v, signedBy(device2Key, device2Cert)));
    }

    @Test
    void binderRejectsACaptureSignedByARevokedDeviceKey() throws Exception {
        JwsVerifier v = with("revoked.crl.pem");
        CaptureBinder binder = new CaptureBinder(v, v, CaptureBinderTest.GOOD, new CaptureBinder.Policy());
        byte[] resp = CaptureBinderTest.response(c -> {
            c.dataKey = device2Key;
            c.dataChain = new X509Certificate[] {device2Cert, CaptureBinderTest.caCert};
            c.idKey = device2Key;
            c.idChain = new X509Certificate[] {device2Cert, CaptureBinderTest.caCert};
        });
        BindingResult b = binder.bind(resp, CaptureBinderTest.ctx(5), Instant.now());
        assertEquals(Outcome.REJECTED + "/" + BindingResult.Reason.UNTRUSTED_DEVICE, b.outcome + "/" + b.reason, b.toString());
        BindingResult ok = binder.bind(CaptureBinderTest.response(c -> { }), CaptureBinderTest.ctx(5), Instant.now());
        assertEquals(Outcome.BOUND, ok.outcome, ok.toString());
    }
}
