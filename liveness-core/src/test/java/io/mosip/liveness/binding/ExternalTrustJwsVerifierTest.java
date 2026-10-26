package io.mosip.liveness.binding;

import io.mosip.liveness.sbi.ExternalTrustJwsVerifier;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.SessionHarness;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionPolicy;
import io.mosip.liveness.streamauth.StreamDigestVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The seam for the Registration Client's kernel {@code jwtVerify}: an external service decides signature and trust;
 * the adapter exposes the x5c leaf for the B1 signer-equality check. The "kernel" here is simulated with the PEM
 * JwsVerifier. [CODE]; the real kernel behaviour is an ASSUMPTION (SBI_INTEGRATION_PLAN Q4).
 */
class ExternalTrustJwsVerifierTest {
    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
    }

    /** Simulated kernel: signature/trust decided by the PEM verifier. */
    static final ExternalTrustJwsVerifier.TrustService KERNEL = jws -> {
        try {
            CaptureBinderTest.verifier.verify(jws, new Date());
            return new ExternalTrustJwsVerifier.Decision(true, true);
        } catch (JwsVerifier.JwsException e) {
            return new ExternalTrustJwsVerifier.Decision(e.reason != JwsVerifier.Reason.BAD_SIGNATURE, false);
        }
    };

    static String signed() throws Exception {
        return CaptureBinderTest.jws(CaptureBinderTest.JSON.createObjectNode().put("k", "v"), CaptureBinderTest.deviceKey,
                CaptureBinderTest.deviceCert, CaptureBinderTest.caCert);
    }

    @Test
    void validTokenExposesTheX5cLeaf() throws Exception {
        JwsVerifier.Verified v = new ExternalTrustJwsVerifier(KERNEL).verify(signed(), new Date());
        assertArrayEquals(CaptureBinderTest.deviceCert.getEncoded(), v.signer.getEncoded());
        assertEquals("v", v.payload.path("k").asText());
    }

    @Test
    void serviceVerdictsMapToJwsReasons() throws Exception {
        String t = signed();
        assertEquals(JwsVerifier.Reason.BAD_SIGNATURE, assertThrows(JwsVerifier.JwsException.class,
                () -> new ExternalTrustJwsVerifier(j -> new ExternalTrustJwsVerifier.Decision(false, false)).verify(t, new Date())).reason);
        assertEquals(JwsVerifier.Reason.UNTRUSTED_CHAIN, assertThrows(JwsVerifier.JwsException.class,
                () -> new ExternalTrustJwsVerifier(j -> new ExternalTrustJwsVerifier.Decision(true, false)).verify(t, new Date())).reason);
        assertEquals(JwsVerifier.Reason.BAD_SIGNATURE, assertThrows(JwsVerifier.JwsException.class,
                () -> new ExternalTrustJwsVerifier(j -> null).verify(t, new Date())).reason);
        assertEquals(JwsVerifier.Reason.MALFORMED, assertThrows(JwsVerifier.JwsException.class,
                () -> new ExternalTrustJwsVerifier(KERNEL).verify("a.b", new Date())).reason);
    }

    @Test
    void failingServiceIsAnExceptionNotAVerdict() throws Exception {
        String t = signed();
        assertThrows(IllegalStateException.class, () -> new ExternalTrustJwsVerifier(j -> {
            throw new java.io.IOException("keymanager down");
        }).verify(t, new Date()));
    }

    @Test
    void b1AndBindingThroughTheAdapterVerifyAndAServiceOutageFailsClosed() throws Exception {
        ExternalTrustJwsVerifier ext = new ExternalTrustJwsVerifier(KERNEL);
        CaptureBinder binder = new CaptureBinder(ext, ext, CaptureBinderTest.stub(1, 0.95f, SessionHarness.SUBJECT), new CaptureBinder.Policy());
        SessionPolicy p = new SessionPolicy();
        p.requireStreamAuthentication = true;
        SessionHarness h = new SessionHarness(p, new AttemptLedger.InMemory(), binder, "L0", new StreamDigestVerifier(ext));
        SessionOutcome o = SessionB1IntegrationTest.attempt(h, x -> { }, f -> { });
        assertEquals(SessionOutcome.State.VERIFIED, o.state, o.toString());
        assertTrue(o.streamAuthenticated);

        ExternalTrustJwsVerifier down = new ExternalTrustJwsVerifier(j -> { throw new java.io.IOException("down"); });
        SessionHarness h2 = new SessionHarness(p, new AttemptLedger.InMemory(), binder, "L0", new StreamDigestVerifier(down));
        SessionOutcome o2 = SessionB1IntegrationTest.attempt(h2, x -> { }, f -> { });
        assertEquals(SessionOutcome.State.ERROR_ENGINE, o2.state, o2.toString());
    }
}
