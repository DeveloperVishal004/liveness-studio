package io.mosip.liveness.sbi;

import java.util.Date;

/**
 * Verification of a device-signed JWS (signature + trust). Implemented by {@link JwsVerifier} (PEM trust anchors, tools
 * and tests) and by {@link ExternalTrustJwsVerifier} (delegates the trust decision, e.g. to the MOSIP kernel
 * {@code SignatureService.jwtVerify(validateTrust=true, domain)} inside the Registration Client).
 */
public interface SignedJwsVerifier {
    JwsVerifier.Verified verify(String compact, Date at) throws JwsVerifier.JwsException;
}
