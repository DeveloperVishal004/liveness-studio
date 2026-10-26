package io.mosip.liveness.streamauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.streamauth.StreamAuthResult.Reason;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * B1 prototype verifier ({@code docs/phase1/B1_STREAM_DIGEST_DESIGN.md}). Checks, in order: statement present and
 * well-formed JWS; signature and chain to the trust anchors; signer = capture signer; nonce, transaction, device,
 * capture hash, freshness; statement sequence and chain; then frame-to-decision coverage, order and missing frames.
 * The first failing check determines the reason.
 *
 * <p>Establishes only that covered frames are byte-identical to frames the device key attested. It does not establish
 * physical liveness and does not protect against a compromised signer (design §1).
 */
public final class StreamDigestVerifier implements StreamAuthenticator {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final io.mosip.liveness.sbi.SignedJwsVerifier jws;

    public StreamDigestVerifier(io.mosip.liveness.sbi.SignedJwsVerifier jws) {
        this.jws = jws;
    }

    private static final class Entry {
        final long seq;
        final long time;
        final byte[] hash;

        Entry(long seq, long time, byte[] hash) {
            this.seq = seq;
            this.time = time;
            this.hash = hash;
        }
    }

    @Override
    public StreamAuthResult verify(byte[] rcaptureResponse, Context ctx, Instant now) {
        JsonNode root;
        try {
            root = JSON.readTree(rcaptureResponse);
        } catch (Exception e) {
            return StreamAuthResult.fail(Reason.MALFORMED, "response not JSON");
        }
        if (root == null || !root.isObject()) {
            return StreamAuthResult.fail(Reason.MALFORMED, "response not an object");
        }
        JsonNode bio = root.path("biometrics").path(0);
        // the statement must sit in the SAME biometrics entry as the capture it names (draft carrier, design §4)
        String statement = bio.path("additionalInfo").path(StreamDigest.ADDITIONAL_INFO_KEY).asText(null);
        if (statement == null || statement.isEmpty()) {
            return StreamAuthResult.fail(Reason.STATEMENT_MISSING, null);
        }
        String captureData = bio.path("data").asText(null);
        if (captureData == null || captureData.isEmpty()) {
            return StreamAuthResult.fail(Reason.CAPTURE_NOT_BOUND, "no capture data in response");
        }
        // 1. signature and chain
        JwsVerifier.Verified st;
        try {
            st = jws.verify(statement, Date.from(now));
        } catch (JwsVerifier.JwsException e) {
            switch (e.reason) {
                case BAD_SIGNATURE: return StreamAuthResult.fail(Reason.BAD_SIGNATURE, null);
                case UNTRUSTED_CHAIN: case CERT_EXPIRED: case CERT_REVOKED: return StreamAuthResult.fail(Reason.UNTRUSTED_SIGNER, e.reason.name());
                default: return StreamAuthResult.fail(Reason.MALFORMED, e.reason.name());
            }
        }
        // 2. same key as the signed capture
        try {
            JwsVerifier.Verified cap = jws.verify(captureData, Date.from(now));
            if (!Arrays.equals(cap.signer.getEncoded(), st.signer.getEncoded())) {
                return StreamAuthResult.fail(Reason.SIGNER_NOT_CAPTURE_DEVICE, null);
            }
        } catch (JwsVerifier.JwsException e) {
            return StreamAuthResult.fail(Reason.CAPTURE_NOT_BOUND, "capture data does not verify: " + e.reason);
        } catch (CertificateEncodingException e) {
            return StreamAuthResult.fail(Reason.MALFORMED, "certificate encoding");
        }
        JsonNode p = st.payload;
        // 3. bindings
        if (!StreamDigest.TYPE.equals(p.path("typ").asText(null))) {
            return StreamAuthResult.fail(Reason.MALFORMED, "typ");
        }
        if (!ctx.transactionId.equals(p.path("transactionId").asText(null))) {
            return StreamAuthResult.fail(Reason.WRONG_TRANSACTION, null);
        }
        if (!ctx.deviceSerial.equals(p.path("deviceSerial").asText(null))) {
            return StreamAuthResult.fail(Reason.WRONG_DEVICE, null);
        }
        String capHash = StreamDigest.b64u(StreamDigest.sha256(captureData.getBytes(StandardCharsets.US_ASCII)));
        if (!capHash.equals(p.path("captureDataSha256").asText(null))) {
            return StreamAuthResult.fail(Reason.CAPTURE_NOT_BOUND, null);
        }
        Instant issued;
        try {
            issued = Instant.parse(p.path("issuedAt").asText(""));
        } catch (DateTimeParseException e) {
            return StreamAuthResult.fail(Reason.MALFORMED, "issuedAt");
        }
        if (issued.isBefore(ctx.windowFrom.minusMillis(ctx.statementSkewMs)) || issued.isAfter(ctx.windowTo.plusMillis(ctx.statementSkewMs))) {
            return StreamAuthResult.fail(Reason.STALE_STATEMENT, issued.toString());
        }
        // 4. statement well-formedness and chain
        JsonNode frames = p.path("frames");
        if (!frames.isArray()) {
            return StreamAuthResult.fail(Reason.MALFORMED, "frames");
        }
        String streamId = p.path("streamId").asText("");
        if (streamId.isEmpty() || streamId.length() > 128) {
            return StreamAuthResult.fail(Reason.MALFORMED, "streamId");
        }
        List<Entry> entries = new ArrayList<>(frames.size());
        byte[] h = StreamDigest.chainSeed(streamId, ctx.deviceSerial);
        long prevTime = Long.MIN_VALUE;
        for (int i = 0; i < frames.size(); i++) {
            JsonNode f = frames.get(i);
            if (!f.isArray() || f.size() != 3 || !f.get(0).canConvertToLong() || !f.get(1).canConvertToLong() || !f.get(2).isTextual()) {
                return StreamAuthResult.fail(Reason.MALFORMED, "frame entry " + i);
            }
            long seq = f.get(0).asLong();
            long t = f.get(1).asLong();
            byte[] fh;
            try {
                fh = StreamDigest.unb64u(f.get(2).asText());
            } catch (IllegalArgumentException e) {
                return StreamAuthResult.fail(Reason.MALFORMED, "frame hash " + i);
            }
            if (fh.length != 32) {
                return StreamAuthResult.fail(Reason.MALFORMED, "frame hash length " + i);
            }
            if (t < prevTime) {
                return StreamAuthResult.fail(Reason.SEQUENCE_REORDER, "device time decreases at " + i);
            }
            prevTime = t;
            h = StreamDigest.chainStep(h, seq, t, fh);
            entries.add(new Entry(seq, t, fh));
        }
        // sequence: any decrease is a reorder (checked over the whole list first); otherwise it must be 0,1,2,... (gap)
        for (int i = 1; i < entries.size(); i++) {
            if (entries.get(i).seq <= entries.get(i - 1).seq) {
                return StreamAuthResult.fail(Reason.SEQUENCE_REORDER, "entry " + i + " seq " + entries.get(i).seq);
            }
        }
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i).seq != i) {
                return StreamAuthResult.fail(Reason.SEQUENCE_GAP, "entry " + i + " seq " + entries.get(i).seq);
            }
        }
        byte[] head;
        try {
            head = StreamDigest.unb64u(p.path("chainHead").asText(""));
        } catch (IllegalArgumentException e) {
            return StreamAuthResult.fail(Reason.MALFORMED, "chainHead");
        }
        if (!Arrays.equals(h, head)) {
            return StreamAuthResult.fail(Reason.CHAIN_MISMATCH, null);
        }
        return coverage(entries, ctx);
    }

    /** Design §6 rules 3–4. */
    private static StreamAuthResult coverage(List<Entry> entries, Context ctx) {
        Map<String, List<Integer>> byHash = new HashMap<>();
        for (int i = 0; i < entries.size(); i++) {
            byHash.computeIfAbsent(StreamDigest.b64u(entries.get(i).hash), k -> new ArrayList<>()).add(i);
        }
        int lastMatched = -1;
        int[] matchedIdx = new int[ctx.received.size()];
        boolean[] entryReceived = new boolean[entries.size()];
        Set<Long> covered = new HashSet<>();
        for (int k = 0; k < ctx.received.size(); k++) {
            FrameRef f = ctx.received.get(k);
            matchedIdx[k] = -1;
            if (f.sha256 == null) {
                if (f.evidence) {
                    return StreamAuthResult.fail(Reason.UNHASHED_FRAME, "tag " + f.tagSeq);
                }
                continue;
            }
            List<Integer> idx = byHash.get(StreamDigest.b64u(f.sha256));
            if (idx == null) {
                continue;                                   // not in the statement: uncovered
            }
            int pick = -1;
            for (int i : idx) {
                if (i > lastMatched) {
                    pick = i;
                    break;
                }
            }
            if (pick < 0) {
                if (f.evidence) {                           // only earlier entries carry this hash: replay/reorder
                    return StreamAuthResult.fail(Reason.FRAME_REORDERED, "tag " + f.tagSeq);
                }
                continue;
            }
            lastMatched = pick;
            matchedIdx[k] = pick;
            entryReceived[pick] = true;
            covered.add(f.tagSeq);
        }
        // coverage of evidence frames, with a bounded trailing suffix
        int lastCoveredEvidence = -1;
        for (int k = 0; k < ctx.received.size(); k++) {
            if (ctx.received.get(k).evidence && matchedIdx[k] >= 0) {
                lastCoveredEvidence = k;
            }
        }
        Set<Long> excluded = new HashSet<>();
        for (int k = 0; k < ctx.received.size(); k++) {
            FrameRef f = ctx.received.get(k);
            if (!f.evidence || matchedIdx[k] >= 0) {
                continue;
            }
            if (k > lastCoveredEvidence && lastCoveredEvidence >= 0 && excluded.size() < ctx.maxUncoveredTail) {
                excluded.add(f.tagSeq);
            } else {
                return StreamAuthResult.fail(Reason.FRAME_NOT_COVERED, "tag " + f.tagSeq);
            }
        }
        // freshness of the covered frames received in the capture window: their DEVICE times must lie in the window
        // (± skew); a delayed / time-shifted stream of authentic frames fails here (adversarial review of B1, R33)
        long lo = ctx.windowFrom.toEpochMilli() - ctx.statementSkewMs, hi = ctx.windowTo.toEpochMilli() + ctx.statementSkewMs;
        for (int k = 0; k < ctx.received.size(); k++) {
            FrameRef f = ctx.received.get(k);
            if (f.inCaptureWindow && matchedIdx[k] >= 0) {
                long t = entries.get(matchedIdx[k]).time;
                if (t < lo || t > hi) {
                    return new StreamAuthResult(Reason.STALE_FRAMES, "tag " + f.tagSeq + " device time " + t + " outside window",
                            covered, excluded, entries.size(), 0);
                }
            }
        }
        // missing signed frames between the first covered window frame and the last covered evidence frame
        int a = -1, b = lastCoveredEvidence >= 0 ? matchedIdx[lastCoveredEvidence] : -1;
        for (int k = 0; k < ctx.received.size(); k++) {
            FrameRef f = ctx.received.get(k);
            if (f.inCaptureWindow && matchedIdx[k] >= 0) {
                a = matchedIdx[k];
                break;
            }
        }
        int missing = 0;
        if (a >= 0 && b >= a) {
            for (int i = a; i <= b; i++) {
                if (!entryReceived[i]) {
                    missing++;
                }
            }
        }
        if (missing > ctx.maxMissingInWindow) {
            return new StreamAuthResult(Reason.MISSING_FRAMES_IN_WINDOW, missing + " signed frames not received",
                    covered, excluded, entries.size(), missing);
        }
        return new StreamAuthResult(Reason.OK, null, covered, excluded, entries.size(), missing);
    }
}
