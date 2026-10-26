package io.mosip.liveness.sbi;

/**
 * Reads JPEG header facts without decoding: dimensions (SOF), progressive flag, and an estimate of the
 * IJG quality factor from the luminance quantisation table (DQT id 0) compared with the IJG standard table.
 * The estimate is meaningful only for IJG-style tables (libjpeg, OpenCV, most camera stacks); vendors with
 * custom tables get a rough figure, reported as such.
 */
public final class JpegInfo {
    private static final int[] STD_LUMA = {   // IJG Annex K table, zig-zag order
        16, 11, 12, 14, 12, 10, 16, 14, 13, 14, 18, 17, 16, 19, 24, 40, 26, 24, 22, 22, 24, 49, 35, 37, 29, 40, 58,
        51, 61, 60, 57, 51, 56, 55, 64, 72, 92, 78, 64, 68, 87, 69, 55, 56, 80, 109, 81, 87, 95, 98, 103, 104, 103,
        62, 77, 113, 121, 112, 100, 120, 92, 101, 103, 99
    };

    public final int width;
    public final int height;
    public final boolean progressive;
    /** Estimated IJG quality 1..100, or -1 if no 8-bit luminance table was found. */
    public final int estimatedQuality;
    /**
     * EXIF orientation tag (1..8), or 0 if absent. Decoders disagree on whether to apply it (OpenCV does, ImageIO
     * does not), so any value other than 0/1 on an SBI stream or capture is a device-integration defect to resolve
     * before models trained/evaluated in one stack are trusted in the other.
     */
    public final int exifOrientation;
    /** Chroma subsampling from the SOF component sampling factors: "4:2:0", "4:2:2", "4:4:4", "grey" or "other". */
    public final String chroma;

    private JpegInfo(int w, int h, boolean progressive, int q, int orientation, String chroma) {
        this.width = w;
        this.height = h;
        this.progressive = progressive;
        this.estimatedQuality = q;
        this.exifOrientation = orientation;
        this.chroma = chroma;
    }

    public static JpegInfo parse(byte[] b) {
        int w = -1, h = -1, q = -1, orientation = 0;
        boolean prog = false;
        String chroma = "unknown";
        int i = 2;
        while (i + 4 <= b.length) {
            if ((b[i] & 0xFF) != 0xFF) {
                i++;
                continue;
            }
            int marker = b[i + 1] & 0xFF;
            if (marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0xFF) {
                i += marker == 0xFF ? 1 : 2;
                continue;
            }
            int len = ((b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
            int seg = i + 4;
            if (len < 2 || seg + len - 2 > b.length) {
                break;
            }
            if (marker == 0xE1 && orientation == 0) {
                orientation = exifOrientation(b, seg, seg + len - 2);
            } else if (marker == 0xDB) {
                int p = seg;
                while (p < seg + len - 2) {
                    int pq = (b[p] & 0xF0) >> 4;
                    int tq = b[p] & 0x0F;
                    int n = pq == 0 ? 64 : 128;
                    if (tq == 0 && pq == 0 && p + 1 + 64 <= b.length) {
                        double s = 0;
                        for (int k = 0; k < 64; k++) {
                            s += (b[p + 1 + k] & 0xFF) * 100.0 / STD_LUMA[k];
                        }
                        s /= 64;
                        q = (int) Math.round(s <= 100 ? (200 - s) / 2 : 5000 / s);
                        q = Math.max(1, Math.min(100, q));
                    }
                    p += 1 + n;
                }
            } else if (marker == 0xC0 || marker == 0xC1 || marker == 0xC2) {
                prog = marker == 0xC2;
                h = ((b[seg + 1] & 0xFF) << 8) | (b[seg + 2] & 0xFF);
                w = ((b[seg + 3] & 0xFF) << 8) | (b[seg + 4] & 0xFF);
                int nc = b[seg + 5] & 0xFF;
                if (nc == 1) {
                    chroma = "grey";
                } else if (nc == 3 && seg + 6 + 9 <= b.length) {
                    int y = b[seg + 7] & 0xFF, cb = b[seg + 10] & 0xFF, cr = b[seg + 13] & 0xFF;
                    int hy = y >> 4, vy = y & 0x0F;
                    if (cb != 0x11 || cr != 0x11) {
                        chroma = "other";
                    } else if (hy == 2 && vy == 2) {
                        chroma = "4:2:0";
                    } else if (hy == 2 && vy == 1) {
                        chroma = "4:2:2";
                    } else if (hy == 1 && vy == 1) {
                        chroma = "4:4:4";
                    } else {
                        chroma = "other";
                    }
                }
            } else if (marker == 0xDA) {
                break; // start of scan: headers are done
            }
            i = seg + len - 2;
        }
        return new JpegInfo(w, h, prog, q, orientation, chroma);
    }

    /** Reads tag 0x0112 from IFD0 of an APP1 "Exif\0\0" segment spanning [start, end). Returns 0 if absent/invalid. */
    static int exifOrientation(byte[] b, int start, int end) {
        if (end - start < 14 || b[start] != 'E' || b[start + 1] != 'x' || b[start + 2] != 'i' || b[start + 3] != 'f') {
            return 0;
        }
        int tiff = start + 6;
        boolean le = b[tiff] == 'I' && b[tiff + 1] == 'I';
        if (!le && !(b[tiff] == 'M' && b[tiff + 1] == 'M')) {
            return 0;
        }
        long ifd = u32(b, tiff + 4, le);
        int p = (int) (tiff + ifd);
        if (ifd < 8 || p + 2 > end) {
            return 0;
        }
        int entries = u16(b, p, le);
        for (int k = 0; k < entries; k++) {
            int e = p + 2 + 12 * k;
            if (e + 12 > end) {
                return 0;
            }
            if (u16(b, e, le) == 0x0112) {
                int v = u16(b, e + 8, le);
                return v >= 1 && v <= 8 ? v : 0;
            }
        }
        return 0;
    }

    private static int u16(byte[] b, int i, boolean le) {
        return le ? (b[i] & 0xFF) | (b[i + 1] & 0xFF) << 8 : (b[i] & 0xFF) << 8 | (b[i + 1] & 0xFF);
    }

    private static long u32(byte[] b, int i, boolean le) {
        return le ? (u16(b, i, true) | ((long) u16(b, i + 2, true) << 16)) : (((long) u16(b, i, false) << 16) | u16(b, i + 2, false));
    }
}
