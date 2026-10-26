package io.mosip.liveness.binding;

/** Outcome of binding a signed RCAPTURE to a liveness session. Contains no biometric data. */
public final class BindingResult {

    public enum Outcome {
        /** Capture is authentic, fresh, from the streaming device, live-looking and the same subject. */
        BOUND,
        /** Capture must not be used; retry may be possible (attempt consumed). */
        REJECTED,
        /** PAD on the signed capture indicates an attack: terminal for the attempt (invariant I1). */
        ATTACK,
        /** Insufficient confidence; treat as a liveness retry/challenge, never as acceptance. */
        UNCERTAIN,
        /** Engine failure: fail closed. */
        ERROR
    }

    public enum Reason {
        OK,
        DEVICE_ERROR, MALFORMED_RESPONSE,
        BAD_SIGNATURE, UNTRUSTED_DEVICE, DIGITAL_ID_INVALID, DEVICE_MISMATCH,
        TRANSACTION_MISMATCH, CAPTURE_STALE, CAPTURE_FROM_FUTURE, REPLAYED_RESPONSE, CAPTURE_OUTSIDE_WINDOW,
        /** Authenticated payload from the expected device, not a replay, but without a transactionId (device fault). */
        TRANSACTION_ABSENT,
        /** Authenticated, bound payload whose content is malformed or incomplete, e.g. timestamp (device fault). */
        MALFORMED_CONTENT,
        BAD_BIO_FORMAT, NO_FACE, MULTIPLE_FACES,
        PAD_ATTACK, PAD_UNCERTAIN,
        INSUFFICIENT_STREAM_EVIDENCE, SUBJECT_MISMATCH,
        ENGINE_ERROR
    }

    public final Outcome outcome;
    public final Reason reason;
    public final String detail;
    public final Float padRealProbability;
    public final Float subjectCosine;
    /** SHA-256 (hex) of the signed {@code data} JWS; recorded in the liveness result (invariant I10). */
    public final String signedDataSha256;
    public final long elapsedNanos;
    /** Image decode (ISO parse + JPEG/JPEG 2000) and vision analysis time; 0 if not reached. */
    public final long decodeNanos;
    public final long analyzeNanos;
    /** Embedding of the signed capture's face (memory only; never logged). Null unless analysis ran. */
    public final float[] captureEmbedding;
    /** Device-signed capture timestamp, if it was parsed. */
    public final java.time.Instant signedTimestamp;

    /**
     * A result built outside {@link CaptureBinder}, for {@code CaptureVerifier} test doubles and adapters. A session
     * trusts whatever its configured verifier returns, so production wiring must use {@link CaptureBinder}.
     */
    public static BindingResult of(Outcome outcome, Reason reason, String signedDataSha256, float[] captureEmbedding) {
        return new BindingResult(outcome, reason, "synthetic", null, null, signedDataSha256, 0, 0, 0, captureEmbedding, null);
    }

    BindingResult(Outcome outcome, Reason reason, String detail, Float pad, Float cos, String hash, long elapsedNanos,
                  long decodeNanos, long analyzeNanos, float[] captureEmbedding, java.time.Instant signedTimestamp) {
        this.captureEmbedding = captureEmbedding;
        this.signedTimestamp = signedTimestamp;
        this.outcome = outcome;
        this.reason = reason;
        this.detail = detail;
        this.padRealProbability = pad;
        this.subjectCosine = cos;
        this.signedDataSha256 = hash;
        this.elapsedNanos = elapsedNanos;
        this.decodeNanos = decodeNanos;
        this.analyzeNanos = analyzeNanos;
    }

    @Override
    public String toString() {
        return outcome + "/" + reason + (detail == null ? "" : " (" + detail + ")")
                + (padRealProbability == null ? "" : String.format(" pad=%.3f", padRealProbability))
                + (subjectCosine == null ? "" : String.format(" cos=%.3f", subjectCosine))
                + String.format(" %.1fms", elapsedNanos / 1e6);
    }
}
