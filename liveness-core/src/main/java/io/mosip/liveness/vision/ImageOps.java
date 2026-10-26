package io.mosip.liveness.vision;

/**
 * Pixel operations that reproduce the OpenCV calls used by the Python reference pipeline closely enough for
 * score parity (validated by golden-vector tests, not assumed):
 * <ul>
 *   <li>{@link #resizeBilinear} ~ {@code cv2.resize(..., INTER_LINEAR)} (half-pixel centres, edge clamp);</li>
 *   <li>{@link #warpAffine} ~ {@code cv2.warpAffine(..., INTER_LINEAR, BORDER_CONSTANT=0)};</li>
 *   <li>{@link #similarityTransform} ~ the 5-point similarity used for SFace alignment.</li>
 * </ul>
 * OpenCV uses fixed-point arithmetic for 8-bit images, so individual pixels can differ by 1 LSB.
 */
public final class ImageOps {
    private ImageOps() {}

    /** Crops {@code [x0,x1) x [y0,y1)} (clamped) and resizes to {@code outW x outH}, writing CHW float planes. */
    public static void cropResizeToChw(BgrImage src, int x0, int y0, int x1, int y1, int outW, int outH,
                                       float[] dst, int dstOffset) {
        x0 = clamp(x0, 0, src.width - 1);
        y0 = clamp(y0, 0, src.height - 1);
        x1 = clamp(x1, x0 + 1, src.width);
        y1 = clamp(y1, y0 + 1, src.height);
        int cw = x1 - x0;
        int ch = y1 - y0;
        double sx = (double) cw / outW;
        double sy = (double) ch / outH;
        int plane = outW * outH;
        byte[] d = src.data;
        int stride = src.width * 3;
        for (int oy = 0; oy < outH; oy++) {
            double fy = (oy + 0.5) * sy - 0.5;
            int iy = (int) Math.floor(fy);
            double wy = fy - iy;
            int ya = clamp(iy, 0, ch - 1) + y0;
            int yb = clamp(iy + 1, 0, ch - 1) + y0;
            for (int ox = 0; ox < outW; ox++) {
                double fx = (ox + 0.5) * sx - 0.5;
                int ix = (int) Math.floor(fx);
                double wx = fx - ix;
                int xa = (clamp(ix, 0, cw - 1) + x0) * 3;
                int xb = (clamp(ix + 1, 0, cw - 1) + x0) * 3;
                int o = dstOffset + oy * outW + ox;
                for (int c = 0; c < 3; c++) {
                    double p00 = d[ya * stride + xa + c] & 0xFF;
                    double p01 = d[ya * stride + xb + c] & 0xFF;
                    double p10 = d[yb * stride + xa + c] & 0xFF;
                    double p11 = d[yb * stride + xb + c] & 0xFF;
                    double v = (p00 * (1 - wx) + p01 * wx) * (1 - wy) + (p10 * (1 - wx) + p11 * wx) * wy;
                    dst[o + c * plane] = (float) Math.rint(v); // cv2 output is uint8
                }
            }
        }
    }

    /** Full-image resize to a BGR byte image (used before detection). */
    public static BgrImage resizeBilinear(BgrImage src, int outW, int outH) {
        float[] chw = new float[outW * outH * 3];
        cropResizeToChw(src, 0, 0, src.width, src.height, outW, outH, chw, 0);
        byte[] out = new byte[outW * outH * 3];
        int plane = outW * outH;
        for (int i = 0; i < plane; i++) {
            out[i * 3] = (byte) (int) chw[i];
            out[i * 3 + 1] = (byte) (int) chw[i + plane];
            out[i * 3 + 2] = (byte) (int) chw[i + 2 * plane];
        }
        return new BgrImage(outW, outH, out);
    }

    /**
     * Inverse-maps each output pixel through the 2x3 forward matrix {@code m} (src -> dst), bilinear, zero border,
     * writing CHW float planes. Matches cv2.warpAffine semantics (no half-pixel shift).
     */
    public static void warpAffineToChw(BgrImage src, double[] m, int outW, int outH, float[] dst) {
        double det = m[0] * m[4] - m[1] * m[3];
        if (Math.abs(det) < 1e-12) {
            throw new IllegalArgumentException("singular affine transform");
        }
        double ia = m[4] / det, ib = -m[1] / det, ic = -m[3] / det, id = m[0] / det;
        double itx = -(ia * m[2] + ib * m[5]);
        double ity = -(ic * m[2] + id * m[5]);
        int plane = outW * outH;
        byte[] d = src.data;
        int stride = src.width * 3;
        for (int y = 0; y < outH; y++) {
            for (int x = 0; x < outW; x++) {
                double sx = ia * x + ib * y + itx;
                double sy = ic * x + id * y + ity;
                int x0 = (int) Math.floor(sx);
                int y0 = (int) Math.floor(sy);
                double wx = sx - x0;
                double wy = sy - y0;
                int o = y * outW + x;
                for (int c = 0; c < 3; c++) {
                    double p00 = px(d, stride, src.width, src.height, x0, y0, c);
                    double p01 = px(d, stride, src.width, src.height, x0 + 1, y0, c);
                    double p10 = px(d, stride, src.width, src.height, x0, y0 + 1, c);
                    double p11 = px(d, stride, src.width, src.height, x0 + 1, y0 + 1, c);
                    double v = (p00 * (1 - wx) + p01 * wx) * (1 - wy) + (p10 * (1 - wx) + p11 * wx) * wy;
                    dst[o + c * plane] = (float) Math.rint(v);
                }
            }
        }
    }

    private static double px(byte[] d, int stride, int w, int h, int x, int y, int c) {
        if (x < 0 || y < 0 || x >= w || y >= h) {
            return 0.0;
        }
        return d[y * stride + x * 3 + c] & 0xFF;
    }

    /**
     * Least-squares similarity transform (rotation, uniform scale, translation) mapping {@code src} points onto
     * {@code dst} points (Umeyama 1991, no reflection). Returns the 2x3 row-major forward matrix.
     */
    public static double[] similarityTransform(float[][] src, float[][] dst) {
        int n = src.length;
        double msx = 0, msy = 0, mdx = 0, mdy = 0;
        for (int i = 0; i < n; i++) {
            msx += src[i][0]; msy += src[i][1]; mdx += dst[i][0]; mdy += dst[i][1];
        }
        msx /= n; msy /= n; mdx /= n; mdy /= n;
        double a = 0, b = 0, var = 0;
        for (int i = 0; i < n; i++) {
            double sx = src[i][0] - msx, sy = src[i][1] - msy;
            double dx = dst[i][0] - mdx, dy = dst[i][1] - mdy;
            a += sx * dx + sy * dy;
            b += sx * dy - sy * dx;
            var += sx * sx + sy * sy;
        }
        if (var < 1e-9) {
            throw new IllegalArgumentException("degenerate landmarks");
        }
        double sc = a / var;
        double sn = b / var;
        double tx = mdx - (sc * msx - sn * msy);
        double ty = mdy - (sn * msx + sc * msy);
        return new double[] {sc, -sn, tx, sn, sc, ty};
    }

    /** Variance of the 4-neighbour Laplacian on the grey ROI: a cheap blur/sharpness proxy (quality gate only). */
    public static double laplacianVariance(BgrImage img, int x0, int y0, int x1, int y1) {
        x0 = clamp(x0, 1, img.width - 2);
        y0 = clamp(y0, 1, img.height - 2);
        x1 = clamp(x1, x0 + 1, img.width - 1);
        y1 = clamp(y1, y0 + 1, img.height - 1);
        double sum = 0, sum2 = 0;
        long n = 0;
        for (int y = y0; y < y1; y++) {
            for (int x = x0; x < x1; x++) {
                double l = grey(img, x - 1, y) + grey(img, x + 1, y) + grey(img, x, y - 1) + grey(img, x, y + 1)
                        - 4 * grey(img, x, y);
                sum += l;
                sum2 += l * l;
                n++;
            }
        }
        double mean = sum / n;
        return sum2 / n - mean * mean;
    }

    /** Mean grey level of an ROI (exposure gate). */
    public static double meanGrey(BgrImage img, int x0, int y0, int x1, int y1) {
        x0 = clamp(x0, 0, img.width - 1);
        y0 = clamp(y0, 0, img.height - 1);
        x1 = clamp(x1, x0 + 1, img.width);
        y1 = clamp(y1, y0 + 1, img.height);
        double s = 0;
        for (int y = y0; y < y1; y++) {
            for (int x = x0; x < x1; x++) {
                s += grey(img, x, y);
            }
        }
        return s / ((double) (x1 - x0) * (y1 - y0));
    }

    private static double grey(BgrImage img, int x, int y) {
        int i = (y * img.width + x) * 3;
        return 0.114 * (img.data[i] & 0xFF) + 0.587 * (img.data[i + 1] & 0xFF) + 0.299 * (img.data[i + 2] & 0xFF);
    }

    static int clamp(int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }
}
