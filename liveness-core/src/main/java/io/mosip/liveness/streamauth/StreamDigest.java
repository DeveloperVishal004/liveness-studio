package io.mosip.liveness.streamauth;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Canonical hashing for the B1 prototype ({@code docs/phase1/B1_STREAM_DIGEST_DESIGN.md} §4). PROTOTYPE format
 * {@code phase0-b1-stream-digest/0}: not an SBI wire format.
 */
public final class StreamDigest {
    private StreamDigest() {}

    public static final String TYPE = "phase0-b1-stream-digest/1";
    /**
     * DRAFT carrier: key inside {@code biometrics[i].additionalInfo} of the RCAPTURE response, a string map the desktop
     * Registration Client's SBI 1.0 DTO already declares and parses (unknown top-level or entry fields make its default
     * ObjectMapper fail). Not defined by the SBI 1.0 text; needs spec-owner agreement (design §9).
     */
    public static final String ADDITIONAL_INFO_KEY = "streamDigest";

    public static byte[] sha256(byte[] b) {
        return md().digest(b);
    }

    /** h0 = SHA-256("phase0-b1/1" || streamId || 0x00 || deviceSerial); streamId is chosen by the device per STREAM. */
    public static byte[] chainSeed(String streamId, String deviceSerial) {
        MessageDigest d = md();
        d.update("phase0-b1/1".getBytes(StandardCharsets.US_ASCII));
        d.update(streamId.getBytes(StandardCharsets.UTF_8));
        d.update((byte) 0);
        d.update(deviceSerial.getBytes(StandardCharsets.UTF_8));
        return d.digest();
    }

    /** h_i = SHA-256(h_{i-1} || u64be(seq) || u64be(deviceTimeMillis) || frameHash). */
    public static byte[] chainStep(byte[] prev, long seq, long deviceTimeMillis, byte[] frameHash) {
        MessageDigest d = md();
        d.update(prev);
        d.update(ByteBuffer.allocate(16).putLong(seq).putLong(deviceTimeMillis).array());
        d.update(frameHash);
        return d.digest();
    }

    public static String b64u(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static byte[] unb64u(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    private static MessageDigest md() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
