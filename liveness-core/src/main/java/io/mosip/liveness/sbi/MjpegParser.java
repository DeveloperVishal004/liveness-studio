package io.mosip.liveness.sbi;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Hardened parser for SBI STREAM bodies ({@code multipart/x-mixed-replace} M-JPEG).
 *
 * <p>Compatible with the MOSIP MockMDS framing (boundary line, {@code Content-Type}, {@code Content-Length},
 * blank line, JPEG, CRLF) and tolerant of vendors that omit the boundary. Differences from the Registration
 * Client's current {@code Streamer.retrieveNextImage}, which reads byte-by-byte and trusts Content-Length:
 * <ul>
 *   <li>buffered reads;</li>
 *   <li>bounded header and frame sizes (a hostile or broken device cannot force huge allocations);</li>
 *   <li>the payload must start with JPEG SOI (FFD8) and end with EOI (FFD9), otherwise it is reported as
 *       corrupt and the parser resynchronises on the next header block;</li>
 *   <li>falls back to SOI..EOI scanning when no Content-Length is present.</li>
 * </ul>
 * Not thread-safe; one instance per stream.
 */
public final class MjpegParser {
    public static final int DEFAULT_MAX_FRAME_BYTES = 8 * 1024 * 1024;
    private static final int MAX_HEADER_BYTES = 8 * 1024;

    /** Outcome of one {@link #next()} call. Exactly one of {@code jpeg} / {@code corruptReason} is set. */
    public static final class Part {
        public final byte[] jpeg;
        public final String corruptReason;

        private Part(byte[] jpeg, String corruptReason) {
            this.jpeg = jpeg;
            this.corruptReason = corruptReason;
        }

        public boolean isValid() { return jpeg != null; }
    }

    private final InputStream in;
    private final int maxFrameBytes;
    private long validParts;
    private long corruptParts;

    public MjpegParser(InputStream in) {
        this(in, DEFAULT_MAX_FRAME_BYTES);
    }

    public MjpegParser(InputStream in, int maxFrameBytes) {
        this.in = in instanceof BufferedInputStream ? in : new BufferedInputStream(in, 64 * 1024);
        this.maxFrameBytes = maxFrameBytes;
    }

    public long validParts() { return validParts; }
    public long corruptParts() { return corruptParts; }

    /**
     * Reads the next part. Returns a corrupt {@link Part} (never throws) for malformed payloads so callers can
     * count and continue; throws {@link EOFException} when the stream ends and {@link IOException} on I/O errors.
     */
    public Part next() throws IOException {
        int contentLength = -1;
        boolean sawHeader = false;
        int headerBytes = 0;
        while (true) {
            String line = readLine();
            if (line == null) {
                throw new EOFException("stream closed");
            }
            headerBytes += line.length() + 2;
            if (headerBytes > MAX_HEADER_BYTES) {
                return corrupt("header block exceeds " + MAX_HEADER_BYTES + " bytes");
            }
            if (line.isEmpty()) {
                if (sawHeader) {
                    break;           // end of this part's header block
                }
                continue;            // CRLF trailing the previous payload
            }
            if (line.startsWith("--")) {
                continue;            // boundary
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                return corrupt("malformed header line");
            }
            sawHeader = true;
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            if (name.equals("content-length")) {
                try {
                    contentLength = Integer.parseInt(line.substring(colon + 1).trim());
                } catch (NumberFormatException e) {
                    return corrupt("non-numeric Content-Length");
                }
            }
        }
        byte[] payload;
        if (contentLength >= 0) {
            if (contentLength < 4 || contentLength > maxFrameBytes) {
                return corrupt("Content-Length out of bounds: " + contentLength);
            }
            payload = readFully(contentLength);
        } else {
            payload = scanSoiToEoi();
            if (payload == null) {
                return corrupt("no JPEG SOI/EOI within " + maxFrameBytes + " bytes");
            }
        }
        if (!isCompleteJpeg(payload)) {
            return corrupt("payload is not a complete JPEG (SOI/EOI)");
        }
        validParts++;
        return new Part(payload, null);
    }

    static boolean isCompleteJpeg(byte[] b) {
        int n = b.length;
        if (n < 4 || (b[0] & 0xFF) != 0xFF || (b[1] & 0xFF) != 0xD8) {
            return false;
        }
        // Some encoders pad after EOI; accept EOI within the last 16 bytes.
        for (int i = n - 2; i >= Math.max(2, n - 16); i--) {
            if ((b[i] & 0xFF) == 0xFF && (b[i + 1] & 0xFF) == 0xD9) {
                return true;
            }
        }
        return false;
    }

    private Part corrupt(String reason) {
        corruptParts++;
        return new Part(null, reason);
    }

    private String readLine() throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream(64);
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                byte[] b = line.toByteArray();
                int len = (b.length > 0 && b[b.length - 1] == '\r') ? b.length - 1 : b.length;
                return new String(b, 0, len, StandardCharsets.ISO_8859_1);
            }
            line.write(c);
            if (line.size() > MAX_HEADER_BYTES) {
                return new String(line.toByteArray(), StandardCharsets.ISO_8859_1); // caller rejects
            }
        }
        return line.size() == 0 ? null : new String(line.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    private byte[] readFully(int len) throws IOException {
        byte[] buf = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(buf, off, len - off);
            if (r < 0) {
                throw new EOFException("stream ended inside a frame (" + off + "/" + len + " bytes)");
            }
            off += r;
        }
        return buf;
    }

    private byte[] scanSoiToEoi() throws IOException {
        int prev = -1;
        int c;
        while ((c = in.read()) != -1) {           // find SOI
            if (prev == 0xFF && c == 0xD8) {
                break;
            }
            prev = c;
        }
        if (c == -1) {
            throw new EOFException("stream closed");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(64 * 1024);
        out.write(0xFF);
        out.write(0xD8);
        prev = -1;
        while ((c = in.read()) != -1) {
            out.write(c);
            if (prev == 0xFF && c == 0xD9) {
                return out.toByteArray();
            }
            if (out.size() > maxFrameBytes) {
                return null;
            }
            prev = c;
        }
        throw new EOFException("stream ended inside a frame");
    }
}
