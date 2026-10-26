package io.mosip.liveness.binding;

import com.fasterxml.jackson.databind.node.ArrayNode;
import io.mosip.liveness.streamauth.StreamAuthResult;
import io.mosip.liveness.streamauth.StreamAuthResult.Outcome;
import io.mosip.liveness.streamauth.StreamAuthResult.Reason;
import io.mosip.liveness.streamauth.StreamAuthenticator;
import io.mosip.liveness.streamauth.StreamAuthenticator.FrameRef;
import io.mosip.liveness.streamauth.StreamDigest;
import io.mosip.liveness.streamauth.StreamDigestVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B1 prototype verifier, cryptographic and frame-to-decision binding checks, with real RS256 signatures from TEST-ONLY
 * keys. [CODE]. Each negative test asserts the exact reason and its class (protocol vs integrity failure).
 */
class StreamDigestVerifierTest {
    static PrivateKey device2Key;
    static X509Certificate device2Cert, expiredCert;
    static final String TXN = "txn-1";

    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
        device2Key = CaptureBinderTest.key("/keys/device2.key");
        device2Cert = CaptureBinderTest.cert("/keys/device2.pem");
        expiredCert = CaptureBinderTest.cert("/keys/expired.pem");
    }

    final StreamDigestVerifier verifier = new StreamDigestVerifier(CaptureBinderTest.verifier);

    /** Device emits 30 frames; client receives all; frames 0..29 are evidence; window = last 10. */
    static final class Case {
        final B1Fixture fx = new B1Fixture(TXN);
        final List<FrameRef> received = new ArrayList<>();
        String ctxTxn = TXN, ctxSerial = CaptureBinderTest.SERIAL;
        int tail = 2, missing = 2;
        Instant now = Instant.now();

        Case() {
            long t0 = now.toEpochMilli() - 3000;
            for (int i = 0; i < 30; i++) {
                fx.emit(B1Fixture.frameBytes(i), t0 + i * 67L);
                received.add(new FrameRef(i, StreamDigest.sha256(B1Fixture.frameBytes(i)), true, i >= 20));
            }
        }

        StreamAuthResult run(StreamDigestVerifier v) throws Exception {
            byte[] resp = fx.attach(CaptureBinderTest.response(c -> c.txn = TXN));
            return run(v, resp);
        }

        StreamAuthResult run(StreamDigestVerifier v, byte[] resp) {
            return v.verify(resp, new StreamAuthenticator.Context(ctxTxn, ctxSerial, now.minusSeconds(2),
                    now.plusMillis(100), received, tail, missing, 5_000), now);
        }
    }

    StreamAuthResult run(Consumer<Case> edit) throws Exception {
        Case c = new Case();
        edit.accept(c);
        return c.run(verifier);
    }

    static void expect(StreamAuthResult r, Reason reason) {
        assertEquals(reason, r.reason, r.toString());
        assertEquals(reason.outcome(), r.outcome);
    }

    // ================================================================ cryptographic verification
    @Test
    void validStatementAuthenticatesEveryReceivedFrame() throws Exception {
        StreamAuthResult r = run(c -> { });
        expect(r, Reason.OK);
        assertEquals(30, r.coveredTags.size());
        assertEquals(0, r.missingInWindow);
    }

    @Test
    void tamperedStatementFailsSignature() throws Exception {
        expect(run(c -> c.fx.tamper = true), Reason.BAD_SIGNATURE);
    }

    @Test
    void untrustedOrExpiredSignerIsRejected() throws Exception {
        expect(run(c -> { c.fx.key = CaptureBinderTest.rogueKey; c.fx.chain = new X509Certificate[] {CaptureBinderTest.rogueCert}; }),
                Reason.UNTRUSTED_SIGNER);
        expect(run(c -> c.fx.chain = new X509Certificate[] {expiredCert, CaptureBinderTest.caCert}), Reason.UNTRUSTED_SIGNER);
    }

    @Test
    void anotherValidDeviceKeyWithTheSameSerialIsRejected() throws Exception {
        expect(run(c -> { c.fx.key = device2Key; c.fx.chain = new X509Certificate[] {device2Cert, CaptureBinderTest.caCert}; }),
                Reason.SIGNER_NOT_CAPTURE_DEVICE);
    }

    @Test
    void missingOrMalformedStatementIsAProtocolFailure() throws Exception {
        Case c = new Case();
        expect(c.run(verifier, CaptureBinderTest.response(x -> x.txn = TXN)), Reason.STATEMENT_MISSING);
        expect(c.run(verifier, "not json".getBytes()), Reason.MALFORMED);
        com.fasterxml.jackson.databind.node.ObjectNode root = (com.fasterxml.jackson.databind.node.ObjectNode)
                CaptureBinderTest.JSON.readTree(CaptureBinderTest.response(x -> x.txn = TXN));
        ((com.fasterxml.jackson.databind.node.ObjectNode) root.path("biometrics").path(0)).putObject("additionalInfo")
                .put(StreamDigest.ADDITIONAL_INFO_KEY, "a.b");
        expect(c.run(verifier, CaptureBinderTest.JSON.writeValueAsBytes(root)), Reason.MALFORMED);
        expect(run(x -> x.fx.editPayload = p -> p.put("typ", "something-else")), Reason.MALFORMED);
    }

    // ================================================================ session / transaction binding
    @Test
    void replayAcrossSessionsFailsOnTheTransaction() throws Exception {
        // a valid statement from another session necessarily names that session's (different) RCAPTURE transaction
        expect(run(c -> c.ctxTxn = "txn-of-this-session"), Reason.WRONG_TRANSACTION);
    }

    @Test
    void statementAtThePrototypeV0TopLevelFieldIsNotRead() throws Exception {
        expect(run(c -> c.fx.topLevelCarrier = true), Reason.STATEMENT_MISSING);
    }

    @Test
    void missingStreamIdIsMalformed() throws Exception {
        expect(run(c -> c.fx.editPayload = p -> p.remove("streamId")), Reason.MALFORMED);
    }

    @Test
    void delayedAuthenticStreamFailsTheWindowFreshnessCheck() throws Exception {
        // every frame authentic and in order, but the frames received in the capture window were emitted 8 s earlier
        expect(run(c -> {
            c.fx.times.replaceAll(t -> t - 8_000);
        }), Reason.STALE_FRAMES);
        expect(run(c -> c.fx.times.replaceAll(t -> t - 2_000)), Reason.OK);      // within the 5 s device-clock skew: residual
    }

    @Test
    void wrongTransactionOrDeviceIsRejected() throws Exception {
        expect(run(c -> c.ctxTxn = "txn-2"), Reason.WRONG_TRANSACTION);
        expect(run(c -> c.fx.serial = "OTHER-DEVICE"), Reason.WRONG_DEVICE);
    }

    @Test
    void statementMustNameTheCaptureInTheSameResponse() throws Exception {
        expect(run(c -> c.fx.captureDataOverride = "some.other.capture"), Reason.CAPTURE_NOT_BOUND);
    }

    @Test
    void staleOrFutureStatementIsAProtocolFailure() throws Exception {
        expect(run(c -> c.fx.issuedAt = c.now.minusSeconds(60)), Reason.STALE_STATEMENT);
        expect(run(c -> c.fx.issuedAt = c.now.plusSeconds(60)), Reason.STALE_STATEMENT);
    }

    // ================================================================ statement well-formedness
    @Test
    void sequenceGapReorderAndChainMismatchAreDetected() throws Exception {
        expect(run(c -> c.fx.editPayload = p -> ((ArrayNode) p.get("frames")).remove(10)), Reason.SEQUENCE_GAP);
        expect(run(c -> c.fx.editPayload = p -> {
            ArrayNode f = (ArrayNode) p.get("frames");
            com.fasterxml.jackson.databind.JsonNode a = f.get(10);
            f.set(10, f.get(11));
            f.set(11, a);
        }), Reason.SEQUENCE_REORDER);
        expect(run(c -> c.fx.editPayload = p -> p.put("chainHead", StreamDigest.b64u(new byte[32]))), Reason.CHAIN_MISMATCH);
    }

    // ================================================================ frame-to-decision binding
    @Test
    void substitutedEvidenceFrameIsNotCovered() throws Exception {
        expect(run(c -> c.received.set(15, new FrameRef(15, StreamDigest.sha256("injected".getBytes()), true, false))),
                Reason.FRAME_NOT_COVERED);
    }

    @Test
    void unhashedEvidenceFrameIsRejected() throws Exception {
        expect(run(c -> c.received.set(15, new FrameRef(15, null, true, false))), Reason.UNHASHED_FRAME);
    }

    @Test
    void replayedEarlierGenuineFrameIsReordered() throws Exception {
        // the attacker re-sends genuine frame 3 in place of frame 15
        expect(run(c -> c.received.set(15, new FrameRef(15, StreamDigest.sha256(B1Fixture.frameBytes(3)), true, false))),
                Reason.FRAME_REORDERED);
    }

    @Test
    void reorderedReceiptIsDetected() throws Exception {
        expect(run(c -> {
            FrameRef a = c.received.get(12);
            c.received.set(12, c.received.get(13));
            c.received.set(13, a);
        }), Reason.FRAME_REORDERED);
    }

    @Test
    void suppressedFramesInTheWindowBeyondTheBoundAreAProtocolFailure() throws Exception {
        StreamAuthResult ok = run(c -> { c.received.remove(22); c.received.remove(22); });       // 2 missing: allowed
        expect(ok, Reason.OK);
        assertEquals(2, ok.missingInWindow);
        expect(run(c -> { for (int i = 0; i < 3; i++) c.received.remove(22); }), Reason.MISSING_FRAMES_IN_WINDOW);
    }

    @Test
    void missingFramesOutsideTheWindowAreNotCounted() throws Exception {
        expect(run(c -> { for (int i = 0; i < 5; i++) c.received.remove(5); }), Reason.OK);
    }

    @Test
    void trailingFramesEmittedAfterSigningAreExcludedButBounded() throws Exception {
        StreamAuthResult r = run(c -> {
            c.received.add(new FrameRef(30, StreamDigest.sha256(B1Fixture.frameBytes(30)), true, true));
            c.received.add(new FrameRef(31, StreamDigest.sha256(B1Fixture.frameBytes(31)), true, true));
        });
        expect(r, Reason.OK);
        assertTrue(r.excludedTailTags.contains(30L) && r.excludedTailTags.contains(31L));
        assertTrue(!r.coveredTags.contains(30L));
        expect(run(c -> { for (int i = 30; i < 33; i++) c.received.add(new FrameRef(i, StreamDigest.sha256(B1Fixture.frameBytes(i)), true, true)); }),
                Reason.FRAME_NOT_COVERED);
    }

    @Test
    void uncoveredNonEvidenceFramesDoNotMatterButUncoveredEvidenceDoes() throws Exception {
        expect(run(c -> c.received.add(5, new FrameRef(99, StreamDigest.sha256("noise".getBytes()), false, false))), Reason.OK);
        expect(run(c -> c.received.add(5, new FrameRef(99, StreamDigest.sha256("noise".getBytes()), true, false))), Reason.FRAME_NOT_COVERED);
    }

    @Test
    void outcomeClassesAreNeverAttackVerdicts() {
        for (Reason r : Reason.values()) {
            assertTrue(r.outcome() == Outcome.AUTHENTICATED || r.outcome() == Outcome.PROTOCOL_FAILURE
                    || r.outcome() == Outcome.INTEGRITY_FAILURE);
        }
    }
}
