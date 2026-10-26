package io.mosip.liveness.sbi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Verifies SBI compact JWS (RS256 with an {@code x5c} chain) against a set of trust anchors.
 *
 * <p>Phase-0 stand-in for the Registration Client's {@code SignatureService.jwtVerify(..., validateTrust=true)}.
 * In the client integration this class is replaced by that service; the binding logic must not depend on
 * which implementation is used. Revocation checking is disabled here (offline-first); the production trust
 * store and its revocation policy are owned by the existing MOSIP certificate sync.
 */
public final class JwsVerifier implements SignedJwsVerifier {
    /** Thrown for any signature, format or trust failure; {@link #reason} is machine-readable. */
    public static final class JwsException extends Exception {
        public final Reason reason;

        JwsException(Reason reason, String message, Throwable cause) {
            super(reason + ": " + message, cause);
            this.reason = reason;
        }
    }

    public enum Reason { MALFORMED, UNSUPPORTED_ALG, BAD_SIGNATURE, UNTRUSTED_CHAIN, CERT_EXPIRED, CERT_REVOKED }

    /** A successfully verified token. */
    public static final class Verified {
        public final JsonNode header;
        public final JsonNode payload;
        public final byte[] payloadBytes;
        public final X509Certificate signer;
        public final String compact;

        Verified(JsonNode header, JsonNode payload, byte[] payloadBytes, X509Certificate signer, String compact) {
            this.header = header;
            this.payload = payload;
            this.payloadBytes = payloadBytes;
            this.signer = signer;
            this.compact = compact;
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private final Set<TrustAnchor> anchors;
    private final List<X509CRL> crls;

    public JwsVerifier(Collection<X509Certificate> trustAnchors) {
        this(trustAnchors, java.util.Collections.emptyList());
    }

    /**
     * With CRLs, PKIX revocation checking is enabled (offline: only the given CRLs; no CRL-DP fetch, no OCSP). A
     * revoked certificate yields {@link Reason#CERT_REVOKED}. If revocation status cannot be determined for a
     * certificate in the path (no CRL from its issuer, or the CRL is past nextUpdate) the path is rejected
     * ({@link Reason#UNTRUSTED_CHAIN}: fail closed). Without CRLs, revocation is not checked (previous behaviour).
     */
    public JwsVerifier(Collection<X509Certificate> trustAnchors, Collection<X509CRL> crls) {
        if (trustAnchors.isEmpty()) {
            throw new IllegalArgumentException("at least one trust anchor is required");
        }
        Set<TrustAnchor> a = new HashSet<>();
        for (X509Certificate c : trustAnchors) {
            a.add(new TrustAnchor(c, null));
        }
        this.anchors = a;
        this.crls = new ArrayList<>(crls);
    }

    /** Trust anchors from a PEM bundle plus CRLs (PEM or DER files). */
    public static JwsVerifier fromPem(Path pem, List<Path> crlFiles) throws IOException, GeneralSecurityException {
        JwsVerifier anchorsOnly = fromPem(pem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509CRL> loaded = new ArrayList<>();
        for (Path p : crlFiles) {
            try (InputStream in = Files.newInputStream(p)) {
                for (java.security.cert.CRL c : cf.generateCRLs(in)) {
                    loaded.add((X509CRL) c);
                }
            }
        }
        List<X509Certificate> roots = new ArrayList<>();
        for (TrustAnchor t : anchorsOnly.anchors) {
            roots.add(t.getTrustedCert());
        }
        return new JwsVerifier(roots, loaded);
    }

    public boolean revocationChecked() { return !crls.isEmpty(); }

    public static JwsVerifier fromPem(Path pem) throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(pem)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>();
            for (Certificate c : cf.generateCertificates(in)) {
                certs.add((X509Certificate) c);
            }
            return new JwsVerifier(certs);
        }
    }

    @Override
    public Verified verify(String compact, Date at) throws JwsException {
        if (compact == null) {
            throw new JwsException(Reason.MALFORMED, "null token", null);
        }
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new JwsException(Reason.MALFORMED, "expected 3 non-empty segments", null);
        }
        JsonNode header;
        byte[] payloadBytes;
        JsonNode payload;
        byte[] sig;
        try {
            header = JSON.readTree(b64url(parts[0]));
            payloadBytes = b64url(parts[1]);
            payload = JSON.readTree(payloadBytes);
            sig = b64url(parts[2]);
        } catch (IOException | IllegalArgumentException e) {
            throw new JwsException(Reason.MALFORMED, "undecodable segment", e);
        }
        if (!"RS256".equals(header.path("alg").asText())) {
            throw new JwsException(Reason.UNSUPPORTED_ALG, header.path("alg").asText(), null);
        }
        List<X509Certificate> chain = x5c(header);
        X509Certificate leaf = chain.get(0);
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(leaf.getPublicKey());
            s.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!s.verify(sig)) {
                throw new JwsException(Reason.BAD_SIGNATURE, "signature does not verify", null);
            }
        } catch (GeneralSecurityException e) {
            throw new JwsException(Reason.BAD_SIGNATURE, "signature verification error", e);
        }
        try {
            leaf.checkValidity(at);
        } catch (GeneralSecurityException e) {
            throw new JwsException(Reason.CERT_EXPIRED, "signer certificate not valid at " + at, e);
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // The path excludes any self-signed root the device may have appended; the anchor supplies it.
            List<X509Certificate> path = new ArrayList<>();
            for (X509Certificate c : chain) {
                if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) {
                    path.add(c);
                }
            }
            if (path.isEmpty()) {
                throw new JwsException(Reason.UNTRUSTED_CHAIN, "self-signed signer", null);
            }
            CertPath cp = cf.generateCertPath(path);
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(!crls.isEmpty());
            if (!crls.isEmpty()) {
                params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls)));
            }
            params.setDate(at);
            CertPathValidator.getInstance("PKIX").validate(cp, params);
        } catch (CertPathValidatorException e) {
            if (e.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                throw new JwsException(Reason.CERT_REVOKED, "certificate revoked", e);
            }
            throw new JwsException(Reason.UNTRUSTED_CHAIN, e.getReason() == CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS
                    ? "revocation status undetermined (no current CRL): fail closed"
                    : "certificate path does not chain to a trust anchor", e);
        } catch (GeneralSecurityException e) {
            throw new JwsException(Reason.UNTRUSTED_CHAIN, "certificate path does not chain to a trust anchor", e);
        }
        return new Verified(header, payload, payloadBytes, leaf, compact);
    }

    /** Decodes the payload without verifying it. Only for diagnostics; never for decisions. */
    public static JsonNode unverifiedPayload(String compact) throws IOException {
        String[] parts = compact.split("\\.", -1);
        if (parts.length < 2) {
            throw new IOException("not a JWS");
        }
        return JSON.readTree(b64url(parts[1]));
    }

    private static List<X509Certificate> x5c(JsonNode header) throws JwsException {
        JsonNode x5c = header.path("x5c");
        if (!x5c.isArray() || x5c.size() == 0) {
            throw new JwsException(Reason.MALFORMED, "missing x5c", null);
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> out = new ArrayList<>();
            for (JsonNode n : x5c) {
                byte[] der = Base64.getDecoder().decode(n.asText());
                out.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
            }
            return out;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new JwsException(Reason.MALFORMED, "invalid x5c certificate", e);
        }
    }

    static byte[] b64url(String s) {
        return Base64.getUrlDecoder().decode(s);
    }
}
