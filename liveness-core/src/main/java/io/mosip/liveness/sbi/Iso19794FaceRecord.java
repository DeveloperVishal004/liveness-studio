package io.mosip.liveness.sbi;

import java.nio.ByteBuffer;
import java.nio.BufferUnderflowException;
import java.util.Arrays;

/**
 * Minimal, bounds-checked reader for an ISO/IEC 19794-5:2011 face record ("FAC\0" / "030\0") with a single
 * representation, as returned in SBI RCAPTURE {@code bioValue} for Face.
 *
 * <p>Byte layout was derived from MOSIP MockMDS {@code Profile/Default/Registration/Face.iso} and checked field
 * by field against its declared lengths (record length, representation length, image data length). The full
 * standard has optional blocks this reader rejects rather than guesses at; production code should use MOSIP
 * {@code biometrics-util} {@code FaceDecoder}, which the Registration Client already depends on, and this class
 * exists so Phase 0 can run without the MOSIP artifact repository.
 */
public final class Iso19794FaceRecord {
    public static final int TYPE_JPEG = 0;
    public static final int TYPE_JPEG2000_LOSSY = 1;
    public static final int TYPE_JPEG2000_LOSSLESS = 2;
    public static final int TYPE_PNG = 3;

    private static final byte[] FORMAT_ID = {'F', 'A', 'C', 0};
    private static final byte[] VERSION_030 = {'0', '3', '0', 0};
    private static final int GENERAL_HEADER = 17;
    private static final int FACIAL_INFO = 15;
    private static final int LANDMARK_BYTES = 8;

    public final int imageDataType;
    public final int width;
    public final int height;
    public final int captureYear;
    public final byte[] imageData;

    private Iso19794FaceRecord(int imageDataType, int width, int height, int captureYear, byte[] imageData) {
        this.imageDataType = imageDataType;
        this.width = width;
        this.height = height;
        this.captureYear = captureYear;
        this.imageData = imageData;
    }

    public static Iso19794FaceRecord parse(byte[] rec) {
        try {
            ByteBuffer b = ByteBuffer.wrap(rec);
            byte[] fmt = new byte[4];
            byte[] ver = new byte[4];
            b.get(fmt).get(ver);
            if (!Arrays.equals(fmt, FORMAT_ID) || !Arrays.equals(ver, VERSION_030)) {
                throw new IllegalArgumentException("not an ISO/IEC 19794-5:2011 face record");
            }
            long recordLength = Integer.toUnsignedLong(b.getInt());
            if (recordLength != rec.length) {
                throw new IllegalArgumentException("record length " + recordLength + " != " + rec.length);
            }
            int reps = Short.toUnsignedInt(b.getShort());
            if (reps != 1) {
                throw new IllegalArgumentException("expected exactly 1 representation, got " + reps);
            }
            b.get();      // certification flag
            b.getShort(); // temporal semantics
            int repStart = b.position();
            long repLength = Integer.toUnsignedLong(b.getInt());
            if (repStart + repLength != rec.length) {
                throw new IllegalArgumentException("representation length mismatch");
            }
            int year = Short.toUnsignedInt(b.getShort());
            b.position(b.position() + 7);            // month..millis
            b.position(b.position() + 1 + 2 + 2);    // capture technology, vendor id, type id
            int qualityBlocks = Byte.toUnsignedInt(b.get());
            b.position(b.position() + 5 * qualityBlocks);
            int landmarks = Short.toUnsignedInt(b.getShort());
            b.position(b.position() + FACIAL_INFO + LANDMARK_BYTES * landmarks);
            b.get();                                 // face image type
            int dataType = Byte.toUnsignedInt(b.get());
            int w = Short.toUnsignedInt(b.getShort());
            int h = Short.toUnsignedInt(b.getShort());
            b.position(b.position() + 5);            // spatial sampling, post-acquisition, cross-ref, colour space
            long dataLength = Integer.toUnsignedLong(b.getInt());
            if (dataLength != b.remaining()) {
                throw new IllegalArgumentException("image data length " + dataLength + " != remaining " + b.remaining());
            }
            if (w == 0 || h == 0 || w > 8192 || h > 8192) {
                throw new IllegalArgumentException("implausible image size " + w + "x" + h);
            }
            byte[] img = new byte[(int) dataLength];
            b.get(img);
            if (GENERAL_HEADER != repStart) {
                throw new IllegalStateException("parser invariant");
            }
            return new Iso19794FaceRecord(dataType, w, h, year, img);
        } catch (BufferUnderflowException | IllegalArgumentException e) {
            if (e instanceof IllegalArgumentException) {
                throw (IllegalArgumentException) e;
            }
            throw new IllegalArgumentException("truncated ISO/IEC 19794-5 record", e);
        }
    }
}
