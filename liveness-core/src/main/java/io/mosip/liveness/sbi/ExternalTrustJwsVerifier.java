package io.mosip.liveness.sbi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

/**
 * Adapter for an external signature/trust service. The service decides signature validity and certificate-path trust;
 * this class only rejects malformed tokens and exposes the {@code x5c} leaf as the signer, which the caller needs for
 * the "statement signer = capture signer" check (B1). ASSUMPTION (unverified, keymanager source not inspected): the
 * service verifies the signature with the {@code x5c} leaf it trusts.
 *
 * <p>Registration Client wiring (illustrative, not applied upstream):
 * <pre>
 * new ExternalTrustJwsVerifier(jws -> {
 *     JWTSignatureVerifyRequestDto r = new JWTSignatureVerifyRequestDto();
 *     r.setValidateTrust(true); r.setDomain(rCaptureTrustDomain); r.setJwtSignatureData(jws);
 *     JWTSignatureVerifyResponseDto v = signatureService.jwtVerify(r);
 *     return new ExternalTrustJwsVerifier.Decision(v.isSignatureValid(), SignatureConstant.TRUST_VALID.equals(v.getTrustValid()));
 * });
 * </pre>
 */
public final class ExternalTrustJwsVerifier implements SignedJwsVerifier {

    public static final class Decision {
        public final boolean signatureValid;
        public final boolean trustValid;

        public Decision(boolean signatureValid, boolean trustValid) {
            this.signatureValid = signatureValid;
            this.trustValid = trustValid;
        }
    }

    @FunctionalInterface
    public interface TrustService {
        Decision check(String compactJws) throws Exception;
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private final TrustService service;

    public ExternalTrustJwsVerifier(TrustService service) {
        this.service = Objects.requireNonNull(service);
    }

    @Override
    public JwsVerifier.Verified verify(String compact, Date at) throws JwsVerifier.JwsException {
        if (compact == null) {
            throw new JwsVerifier.JwsException(JwsVerifier.Reason.MALFORMED, "null token", null);
        }
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new JwsVerifier.JwsException(JwsVerifier.Reason.MALFORMED, "expected 3 non-empty segments", null);
        }
        JsonNode header;
        byte[] payloadBytes;
        JsonNode payload;
        try {
            header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
            payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            payload = JSON.readTree(payloadBytes);
        } catch (Exception e) {
            throw new JwsVerifier.JwsException(JwsVerifier.Reason.MALFORMED, "undecodable segment", e);
        }
        X509Certificate leaf;
        try {
            String der = header.path("x5c").path(0).asText(null);
            if (der == null) {
                throw new JwsVerifier.JwsException(JwsVerifier.Reason.MALFORMED, "no x5c", null);
            }
            leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(der)));
        } catch (CertificateException | IllegalArgumentException e) {
            throw new JwsVerifier.JwsException(JwsVerifier.Reason.MALFORMED, "x5c leaf", e);
        }
        Decision d;
        try {
            d = service.check(compact);
        } catch (Exception e) {
            // a failing trust service is not a verdict on the token; callers fail closed on the exception path
            throw new IllegalStateException("trust service failed", e);
        }
        if (d == null || !d.signatureValid) {
            throw new JwsVerifier.JwsException(JwsVerifier.Reason.BAD_SIGNATURE, "external service: signature invalid", null);
        }
        if (!d.trustValid) {
            throw new JwsVerifier.JwsException(JwsVerifier.Reason.UNTRUSTED_CHAIN, "external service: trust invalid", null);
        }
        return new JwsVerifier.Verified(header, payload, payloadBytes, leaf, compact);
    }
}
