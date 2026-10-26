package io.mosip.liveness.sbi;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MjpegParserTest {

    static byte[] jpeg(int bodyLen, int fill) {
        byte[] b = new byte[bodyLen + 4];
        b[0] = (byte) 0xFF;
        b[1] = (byte) 0xD8;
        for (int i = 2; i < bodyLen + 2; i++) {
            b[i] = (byte) fill;
        }
        b[bodyLen + 2] = (byte) 0xFF;
        b[bodyLen + 3] = (byte) 0xD9;
        return b;
    }

    /** Exactly MockMDS framing (SBIServiceResponse.renderJPGImageData). */
    static void mockMdsPart(ByteArrayOutputStream out, byte[] jpg) throws IOException {
        out.write(("--BoundaryString\r\nAccess-Control-Allow-Origin:*\r\nContent-Type:image/jpeg\r\nContent-Length:"
                + jpg.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(jpg);
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void parsesMockMdsFramingInOrder() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] a = jpeg(100, 1), b = jpeg(5000, 2), c = jpeg(10, 3);
        mockMdsPart(out, a);
        mockMdsPart(out, b);
        mockMdsPart(out, c);
        MjpegParser p = new MjpegParser(new ByteArrayInputStream(out.toByteArray()));
        assertArrayEquals(a, p.next().jpeg);
        assertArrayEquals(b, p.next().jpeg);
        assertArrayEquals(c, p.next().jpeg);
        assertThrows(EOFException.class, p::next);
        assertEquals(3, p.validParts());
    }

    @Test
    void corruptPayloadIsReportedAndParserResynchronises() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] bad = jpeg(50, 7);
        bad[bad.length - 1] = 0x00;                    // EOI destroyed
        mockMdsPart(out, bad);
        byte[] good = jpeg(64, 9);
        mockMdsPart(out, good);
        MjpegParser p = new MjpegParser(new ByteArrayInputStream(out.toByteArray()));
        MjpegParser.Part first = p.next();
        assertFalse(first.isValid());
        assertNotNull(first.corruptReason);
        assertArrayEquals(good, p.next().jpeg);
        assertEquals(1, p.corruptParts());
    }

    @Test
    void oversizeContentLengthIsRejectedWithoutAllocating() throws Exception {
        String s = "--BoundaryString\r\nContent-Type:image/jpeg\r\nContent-Length:2000000000\r\n\r\n";
        MjpegParser p = new MjpegParser(new ByteArrayInputStream(s.getBytes(StandardCharsets.US_ASCII)), 1024 * 1024);
        MjpegParser.Part part = p.next();
        assertFalse(part.isValid());
        assertTrue(part.corruptReason.contains("out of bounds"));
    }

    @Test
    void truncatedFrameAtEndOfStreamIsEof() {
        String s = "--BoundaryString\r\nContent-Length:100\r\n\r\nÿØabc";
        MjpegParser p = new MjpegParser(new ByteArrayInputStream(s.getBytes(StandardCharsets.ISO_8859_1)));
        assertThrows(EOFException.class, p::next);
    }

    @Test
    void fallsBackToSoiEoiScanWithoutContentLength() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] j = jpeg(30, 4);
        out.write("--BoundaryString\r\nContent-Type:image/jpeg\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write(j);
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
        MjpegParser p = new MjpegParser(new ByteArrayInputStream(out.toByteArray()));
        assertArrayEquals(j, p.next().jpeg);
    }

    @Test
    void nonNumericContentLengthIsCorrupt() throws Exception {
        String s = "--BoundaryString\r\nContent-Length: 12abc\r\n\r\n";
        MjpegParser p = new MjpegParser(new ByteArrayInputStream(s.getBytes(StandardCharsets.US_ASCII)));
        assertFalse(p.next().isValid());
    }
}
