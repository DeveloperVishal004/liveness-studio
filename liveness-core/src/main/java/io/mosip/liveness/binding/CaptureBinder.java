package io.mosip.liveness.binding;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.liveness.binding.BindingResult.Outcome;
import io.mosip.liveness.binding.BindingResult.Reason;
import io.mosip.liveness.sbi.Iso19794FaceRecord;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.vision.BgrImage;
import io.mosip.liveness.vision.ImageDecoder;
import io.mosip.liveness.vision.SFaceEmbedder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Binds a device-signed SBI RCAPTURE response to the liveness evidence gathered from the (unsigned) STREAM.
 *
 * <p>Why this exists: on desktop the liveness engine sees unsigned M-JPEG frames, while the image that is stored
 * or matched comes from a separate, device-timed, signed RCAPTURE. Without binding, a live person on the stream and
 * a photo (or a replayed old response) at capture time would pass. Checks, cheapest and most security-relevant first:
 * <ol>
 *   <li>response well-formed, device error code 0;</li>
 *   <li>{@code data} JWS signature and certificate chain valid against the device trust anchors;</li>
 *   <li>not a byte-identical replay of a response this process already accepted or saw;</li>
 *   <li>{@code digitalId} JWS valid and naming the same device (serial/make/model) that produced the stream;</li>
 *   <li>{@code transactionId} equals the unpredictable nonce sent with this request (absent: TRANSACTION_ABSENT;
 *       different: TRANSACTION_MISMATCH) — the SBI 1.0 provider in the Registration Client does not currently check
 *       this (the 0.9.5 provider does);</li>
 *   <li>signed device timestamp present and parseable (else MALFORMED_CONTENT), inside
 *       {@code [sessionStart - skew, now + skew]} and the capture window;</li>
 *   <li>bioValue is a parseable ISO/IEC 19794-5 record with a decodable image;</li>
 *   <li>exactly one face; PAD on the <em>signed</em> image is not an attack ({@link Policy#padAttack}) and, under the
 *       default conservative rule, at least {@link Policy#padCaptureMin};</li>
 *   <li>same subject as the verified stream evidence (median cosine over stream embeddings).</li>
 * </ol>
 * Any exception maps to {@link Outcome#ERROR} or {@link Outcome#REJECTED}; no path returns BOUND by default.
 *
 * <p>Order matters for fault attribution: TRANSACTION_ABSENT, MALFORMED_CONTENT, CAPTURE_STALE, CAPTURE_FROM_FUTURE and
 * CAPTURE_OUTSIDE_WINDOW are reachable only for a response whose signature, trust, replay status and device identity
 * have been verified (and, for the time reasons, whose nonce matched), so a session may treat them as device faults.
 * MALFORMED_RESPONSE is produced BEFORE authentication and cannot be attributed to this request or device.
 */
public final class CaptureBinder implements io.mosip.liveness.session.CaptureVerifier {

    /** Thresholds and tolerances. PAD/subject thresholds here are placeholders until calibrated (Phase-0 E4). */
    public static final class Policy {
        public Duration clockSkew = Duration.ofSeconds(120);
        /**
         * Device-vs-host clock tolerance for the RCAPTURE window check (temporal binding). PROVISIONAL: the real device
         * clock offset is unmeasured (plan T3.1); a device whose clock is off by more than this fails closed (retry).
         */
        public Duration captureWindowSkew = Duration.ofSeconds(5);
        /**
         * Below this capture-PAD value the attempt is ATTACK (both rules). Under the PROPOSED veto-only rule (D4) this
         * is the only capture-PAD check. Phase-0 evidence (mock device, placeholder model): 40 genuine captures of one
         * constant bona fide scene scored a median of 0.78-0.82 (min 0.32), so the accept gate at 0.80 makes about half
         * of genuine captures UNCERTAIN.
         */
        public float padAttack = 0.20f;
        /**
         * Capture-PAD accept floor: below it (and at/above {@link #padAttack}) the capture is UNCERTAIN.
         * <p><b>Default 0.80 = the conservative accept-gate rule (owner decision 2, 2026-10-24).</b> The value 0.80 is
         * PROVISIONAL until calibrated with a production-candidate model on representative data. Veto-only mode must not
         * be enabled; {@link #proposedVetoOnly()} exists only for side-by-side comparison experiments.
         * See docs/phase0/SECURITY_ANALYSIS_CAPTURE_PAD_RULE.md.
         */
        public float padCaptureMin = 0.80f;

        /** Conservative rule (default): capture PAD must be >= 0.80 to bind; < 0.20 is ATTACK. */
        public static Policy conservativeAcceptGate() {
            return new Policy();
        }

        /**
         * Veto-only rule (D4): capture PAD only vetoes (< 0.20 is ATTACK). <b>Not to be enabled</b> (owner decision 2,
         * 2026-10-24); for comparison experiments only (bind-scenarios, probe reports).
         */
        public static Policy proposedVetoOnly() {
            Policy p = new Policy();
            p.padCaptureMin = p.padAttack;
            return p;
        }
        /**
         * Phase-0 E4 (LFW, 75 subjects, 5,550 impostor pairs): same-session genuine cosine >= 0.83, impostor <= 0.41.
         * 0.5 sits inside that gap (0/5,550 impostors pass; 0 same-session misses). OpenCV's published 0.363 let
         * 4/5,550 impostors pass. Recalibrate on device data; feed only frontal stream frames.
         */
        public float subjectMinCosine = 0.50f;
        public int minStreamEmbeddings = 3;
        public int replayCacheSize = 4096;
    }

    /** What the session knows independently of the capture response. */
    public static final class SessionContext {
        public final String expectedTransactionId;
        public final String streamDeviceSerial;
        public final String streamDeviceMake;
        public final String streamDeviceModel;
        public final Instant sessionStart;
        public final List<float[]> streamEmbeddings;
        /** Wall-clock bounds of the RCAPTURE request/response (host), or null. Derived from monotonic time by the caller. */
        public final Instant windowFrom;
        public final Instant windowTo;

        public SessionContext(String expectedTransactionId, String serial, String make, String model,
                              Instant sessionStart, List<float[]> streamEmbeddings) {
            this(expectedTransactionId, serial, make, model, sessionStart, streamEmbeddings, null, null);
        }

        public SessionContext(String expectedTransactionId, String serial, String make, String model,
                              Instant sessionStart, List<float[]> streamEmbeddings, Instant windowFrom, Instant windowTo) {
            this.windowFrom = windowFrom;
            this.windowTo = windowTo;
            this.expectedTransactionId = Objects.requireNonNull(expectedTransactionId);
            this.streamDeviceSerial = Objects.requireNonNull(serial);
            this.streamDeviceMake = make;
            this.streamDeviceModel = model;
            this.sessionStart = Objects.requireNonNull(sessionStart);
            this.streamEmbeddings = Collections.unmodifiableList(new ArrayList<>(streamEmbeddings));
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final io.mosip.liveness.sbi.SignedJwsVerifier dataVerifier;
    private final io.mosip.liveness.sbi.SignedJwsVerifier digitalIdVerifier;
    private final CaptureAnalyzer analyzer;
    private final ImageDecoder decoder = new ImageDecoder();
    private final Policy policy;
    private final Map<String, Boolean> seen;

    public CaptureBinder(io.mosip.liveness.sbi.SignedJwsVerifier dataVerifier, io.mosip.liveness.sbi.SignedJwsVerifier digitalIdVerifier,
                         CaptureAnalyzer analyzer, Policy policy) {
        this.dataVerifier = Objects.requireNonNull(dataVerifier);
        this.digitalIdVerifier = Objects.requireNonNull(digitalIdVerifier);
        this.analyzer = Objects.requireNonNull(analyzer);
        this.policy = Objects.requireNonNull(policy);
        final int cap = policy.replayCacheSize;
        this.seen = Collections.synchronizedMap(new LinkedHashMap<String, Boolean>(64, 0.75f, false) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Boolean> e) {
                return size() > cap;
            }
        });
    }

    /** SFace output: 128 finite components, L2-normalised (same rule the session applies to stream embeddings). */
    static boolean validEmbedding(float[] e) {
        if (e == null || e.length != 128) {
            return false;
        }
        double n = 0;
        for (float x : e) {
            if (!Float.isFinite(x)) {
                return false;
            }
            n += (double) x * x;
        }
        return Math.abs(Math.sqrt(n) - 1.0) < 1e-2;
    }

    @Override
    public BindingResult bind(byte[] rcaptureResponse, SessionContext ctx, Instant now) {
        long t0 = System.nanoTime();
        String hash = null;
        long[] t = timing.get();
        t[0] = 0;
        t[1] = 0;
        t[2] = Long.MIN_VALUE;
        captureEmbedding.set(null);
        try {
            JsonNode root;
            try {
                root = JSON.readTree(rcaptureResponse);
            } catch (Exception e) {
                return done(t0, Outcome.REJECTED, Reason.MALFORMED_RESPONSE, "not JSON", null, null, null);
            }
            JsonNode bios = root.path("biometrics");
            if (!bios.isArray() || bios.size() != 1) {
                return done(t0, Outcome.REJECTED, Reason.MALFORMED_RESPONSE, "expected exactly one biometric", null, null, null);
            }
            JsonNode bio = bios.get(0);
            String err = bio.path("error").path("errorCode").asText("");
            if (!"0".equals(err)) {
                return done(t0, Outcome.REJECTED, Reason.DEVICE_ERROR, "errorCode=" + err, null, null, null);
            }
            String compact = bio.path("data").asText("");
            hash = sha256Hex(compact.getBytes(StandardCharsets.US_ASCII));

            JwsVerifier.Verified data;
            try {
                data = dataVerifier.verify(compact, Date.from(now));
            } catch (JwsVerifier.JwsException e) {
                Reason r = e.reason == JwsVerifier.Reason.UNTRUSTED_CHAIN || e.reason == JwsVerifier.Reason.CERT_EXPIRED
                        || e.reason == JwsVerifier.Reason.CERT_REVOKED
                        ? Reason.UNTRUSTED_DEVICE : (e.reason == JwsVerifier.Reason.MALFORMED ? Reason.MALFORMED_RESPONSE : Reason.BAD_SIGNATURE);
                return done(t0, Outcome.REJECTED, r, e.reason.name(), null, null, hash);
            }

            if (seen.putIfAbsent(hash, Boolean.TRUE) != null) {
                return done(t0, Outcome.REJECTED, Reason.REPLAYED_RESPONSE, null, null, null, hash);
            }

            JsonNode p = data.payload;
            // Device identity BEFORE any device-fault classification: a fault can only be attributed to a response
            // proven to come from this session's device (signature + trust above, signed digitalId + serial here).
            JsonNode digitalId;
            try {
                digitalId = digitalIdVerifier.verify(p.path("digitalId").asText(null), Date.from(now)).payload;
            } catch (JwsVerifier.JwsException e) {
                return done(t0, Outcome.REJECTED, Reason.DIGITAL_ID_INVALID, e.reason.name(), null, null, hash);
            }
            if (!ctx.streamDeviceSerial.equals(digitalId.path("serialNo").asText(null))
                    || (ctx.streamDeviceMake != null && !ctx.streamDeviceMake.equals(digitalId.path("make").asText(null)))
                    || (ctx.streamDeviceModel != null && !ctx.streamDeviceModel.equals(digitalId.path("model").asText(null)))) {
                return done(t0, Outcome.REJECTED, Reason.DEVICE_MISMATCH, null, null, null, hash);
            }

            JsonNode txnNode = p.path("transactionId");
            String txn = txnNode.isTextual() ? txnNode.asText() : (txnNode.isMissingNode() || txnNode.isNull() ? null : txnNode.toString());
            if (txn == null || txn.trim().isEmpty()) {
                // signed by the expected device, not a replay, but carries no nonce: a non-conforming device (fault)
                return done(t0, Outcome.REJECTED, Reason.TRANSACTION_ABSENT, null, null, null, hash);
            }
            if (!constantTimeEquals(txn, ctx.expectedTransactionId)) {
                return done(t0, Outcome.REJECTED, Reason.TRANSACTION_MISMATCH, null, null, null, hash);
            }

            // From here the response is bound to THIS request: time problems are device-clock faults.
            Instant ts = parseTimestamp(p.path("timestamp").asText(null));
            if (ts == null) {
                return done(t0, Outcome.REJECTED, Reason.MALFORMED_CONTENT, "timestamp", null, null, hash);
            }
            if (ts.isBefore(ctx.sessionStart.minus(policy.clockSkew))) {
                return done(t0, Outcome.REJECTED, Reason.CAPTURE_STALE, ts.toString(), null, null, hash);
            }
            if (ts.isAfter(now.plus(policy.clockSkew))) {
                return done(t0, Outcome.REJECTED, Reason.CAPTURE_FROM_FUTURE, ts.toString(), null, null, hash);
            }
            t[2] = ts.toEpochMilli();
            if (ctx.windowFrom != null && ctx.windowTo != null
                    && (ts.isBefore(ctx.windowFrom.minus(policy.captureWindowSkew))
                        || ts.isAfter(ctx.windowTo.plus(policy.captureWindowSkew)))) {
                return done(t0, Outcome.REJECTED, Reason.CAPTURE_OUTSIDE_WINDOW, ts.toString(), null, null, hash);
            }

            if (!"Face".equalsIgnoreCase(p.path("bioType").asText(""))) {
                return done(t0, Outcome.REJECTED, Reason.BAD_BIO_FORMAT, "bioType", null, null, hash);
            }

            BgrImage img;
            long td = System.nanoTime();
            try {
                byte[] iso = Base64.getUrlDecoder().decode(stripPadding(p.path("bioValue").asText("")));
                Iso19794FaceRecord rec = Iso19794FaceRecord.parse(iso);
                img = decoder.decode(rec.imageData);
                if (img.width != rec.width || img.height != rec.height) {
                    return done(t0, Outcome.REJECTED, Reason.BAD_BIO_FORMAT, "header/image size mismatch", null, null, hash);
                }
            } catch (Exception e) {
                return done(t0, Outcome.REJECTED, Reason.BAD_BIO_FORMAT, e.getClass().getSimpleName(), null, null, hash);
            }
            long ta = System.nanoTime();
            t[0] = ta - td;

            CaptureAnalyzer.Analysis a;
            try {
                a = analyzer.analyze(img);
                t[1] = System.nanoTime() - ta;
            } catch (Exception e) {
                return done(t0, Outcome.ERROR, Reason.ENGINE_ERROR, e.getClass().getSimpleName(), null, null, hash);
            }
            if (a.faceCount == 0) {
                return done(t0, Outcome.REJECTED, Reason.NO_FACE, null, null, null, hash);
            }
            if (a.faceCount > 1) {
                return done(t0, Outcome.REJECTED, Reason.MULTIPLE_FACES, null, null, null, hash);
            }
            Float pad = a.padRealProbability;
            if (pad == null || a.embedding == null || !Float.isFinite(pad)) {
                return done(t0, Outcome.ERROR, Reason.ENGINE_ERROR, "missing analysis output", null, null, hash);
            }
            if (pad < 0f || pad > 1f) {                    // a probability outside [0,1] is a broken analyzer, never a pass
                return done(t0, Outcome.ERROR, Reason.ENGINE_ERROR, "PAD score outside [0,1]", null, null, hash);
            }
            if (!validEmbedding(a.embedding)) {            // non-finite, wrong size or not unit length: cosine would be meaningless
                return done(t0, Outcome.ERROR, Reason.ENGINE_ERROR, "invalid subject embedding", null, null, hash);
            }
            captureEmbedding.set(a.embedding);
            if (pad < policy.padAttack) {
                return done(t0, Outcome.ATTACK, Reason.PAD_ATTACK, null, pad, null, hash);
            }

            if (ctx.streamEmbeddings.size() < policy.minStreamEmbeddings) {
                return done(t0, Outcome.UNCERTAIN, Reason.INSUFFICIENT_STREAM_EVIDENCE, null, pad, null, hash);
            }
            float[] cos = new float[ctx.streamEmbeddings.size()];
            for (int i = 0; i < cos.length; i++) {
                cos[i] = SFaceEmbedder.cosine(a.embedding, ctx.streamEmbeddings.get(i));
            }
            Arrays.sort(cos);
            float median = cos[cos.length / 2];
            if (!(median >= policy.subjectMinCosine)) {
                return done(t0, Outcome.REJECTED, Reason.SUBJECT_MISMATCH, null, pad, median, hash);
            }
            if (pad < policy.padCaptureMin) {
                return done(t0, Outcome.UNCERTAIN, Reason.PAD_UNCERTAIN, null, pad, median, hash);
            }
            return done(t0, Outcome.BOUND, Reason.OK, null, pad, median, hash);
        } catch (RuntimeException e) {
            return done(t0, Outcome.ERROR, Reason.ENGINE_ERROR, e.getClass().getSimpleName(), null, null, hash);
        }
    }

    static Instant parseTimestamp(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(s);
        } catch (DateTimeParseException e) {
            try {
                return OffsetDateTime.parse(s).toInstant();
            } catch (DateTimeParseException e2) {
                return null;
            }
        }
    }

    private static String stripPadding(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '=') {
            end--;
        }
        return s.substring(0, end);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    static String sha256Hex(byte[] b) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(b);
            StringBuilder sb = new StringBuilder(64);
            for (byte x : h) {
                sb.append(String.format("%02x", x));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Per-thread [decodeNanos, analyzeNanos] of the bind in progress (bind() may be called from several threads). */
    private final ThreadLocal<long[]> timing = ThreadLocal.withInitial(() -> new long[3]);
    private final ThreadLocal<float[]> captureEmbedding = new ThreadLocal<>();

    private BindingResult done(long t0, Outcome o, Reason r, String detail, Float pad, Float cos, String hash) {
        long[] t = timing.get();
        Instant ts = t[2] == Long.MIN_VALUE ? null : Instant.ofEpochMilli(t[2]);
        return new BindingResult(o, r, detail, pad, cos, hash, System.nanoTime() - t0, t[0], t[1], captureEmbedding.get(), ts);
    }
}
