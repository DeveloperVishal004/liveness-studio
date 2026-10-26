package io.mosip.liveness.session;

import java.util.List;

/**
 * Detects a <em>static image</em> fed as a stream — a frozen MDS/sensor, or a looped still photo re-encoded and moved by
 * small global transforms (shift, rotation, scale, brightness/contrast, noise) — which byte-identity checks miss.
 *
 * <p>For consecutive frames with one face, the landmark-aligned 64x64 grey crops are standardised and the second is
 * registered onto the first by an affine Lucas-Kanade; the statistic is the <b>maximum 8x8-block mean absolute residual</b>
 * ({@link #photoResidual}). A window is {@link Verdict#VARYING} if at least {@code minVaryingPairs} pairs exceed the
 * threshold, otherwise {@link Verdict#STATIC_SUSPECT}. A geometric (affine-landmark) residual is computed for diagnostics
 * only: on the [SIM] fixtures it did not separate the classes.
 *
 * <p><b>What the [SIM] calibration showed (2026-10-24):</b> after registration, ordinary frame pairs of a re-encoded static
 * replay and of the synthetic live stand-in overlap; only <em>localised events such as a blink</em> exceed the static
 * noise floor (static max 0.348 over 4 sources; stand-in max 0.41–0.76). The default threshold 0.40 is therefore an
 * <em>event detector</em>: a window is VARYING only if it contains a blink-like change.
 *
 * <p><b>Limits:</b> (1) a live person who does not blink or move within the window is classified STATIC_SUSPECT — callers
 * must treat it as <em>insufficient evidence</em> (fail closed, retry/challenge), never as an attack; the real-world
 * false-freeze rate is unmeasured. (2) A photo moved in 3-D, a video replay, or an injected stream with synthetic
 * non-rigid warps is not "static" — those are PAD and injection problems (F4). (3) Thresholds are provisional until
 * measured on real devices (plan T3.1).
 */
public final class StaticReplayDetector {

    public enum Verdict { VARYING, STATIC_SUSPECT, INSUFFICIENT_FRAMES }

    public static final class Assessment {
        public final Verdict verdict;
        public final int pairs;
        public final int varyingPairs;
        public final double maxGeom;
        public final double maxPhoto;

        Assessment(Verdict v, int pairs, int varyingPairs, double maxGeom, double maxPhoto) {
            this.verdict = v;
            this.pairs = pairs;
            this.varyingPairs = varyingPairs;
            this.maxGeom = maxGeom;
            this.maxPhoto = maxPhoto;
        }

        @Override
        public String toString() {
            return String.format("%s pairs=%d varying=%d maxGeom=%.4f maxPhoto=%.4f", verdict, pairs, varyingPairs, maxGeom, maxPhoto);
        }
    }

    private final double photoThreshold;
    private final int minPairs;
    private final int minVaryingPairs;

    public StaticReplayDetector(double photoThreshold, int minPairs, int minVaryingPairs) {
        this.photoThreshold = photoThreshold;
        this.minPairs = minPairs;
        this.minVaryingPairs = minVaryingPairs;
    }

    /** @param frames time-ordered records; only those with landmarks and an aligned crop are used */
    public Assessment assess(List<EvidenceRecord> frames) {
        EvidenceRecord prev = null;
        int pairs = 0, varying = 0;
        double maxG = 0, maxP = 0;
        for (EvidenceRecord r : frames) {
            if (r.landmarks == null || r.alignedGrey == null) {
                continue;
            }
            if (prev != null) {
                // cached residual only if it was computed against exactly this predecessor (same result, no recompute)
                boolean cached = r.residualPrevSeq == prev.seq && prev.epoch == r.epoch && !Double.isNaN(r.photoToPrev);
                double g = cached ? r.geomToPrev : geomResidual(prev.landmarks, r.landmarks);
                double p = cached ? r.photoToPrev : photoResidual(prev.alignedGrey, r.alignedGrey);
                pairs++;
                maxG = Math.max(maxG, g);
                maxP = Math.max(maxP, p);
                if (p > photoThreshold) {      // geometric residual is diagnostic only (did not separate on [SIM] data)
                    varying++;
                }
            }
            prev = r;
        }
        if (pairs < minPairs) {
            return new Assessment(Verdict.INSUFFICIENT_FRAMES, pairs, varying, maxG, maxP);
        }
        return new Assessment(varying >= minVaryingPairs ? Verdict.VARYING : Verdict.STATIC_SUSPECT, pairs, varying, maxG, maxP);
    }

    /** Computes and caches r's residuals to its predecessor prev (both usable, same epoch). */
    static void cacheResiduals(EvidenceRecord prev, EvidenceRecord r) {
        if (prev == null || r == null || prev.epoch != r.epoch || prev.landmarks == null || prev.alignedGrey == null
                || r.landmarks == null || r.alignedGrey == null) {
            return;
        }
        r.geomToPrev = geomResidual(prev.landmarks, r.landmarks);
        r.photoToPrev = photoResidual(prev.alignedGrey, r.alignedGrey);
        r.residualPrevSeq = prev.seq;
    }

    /** RMS landmark residual after a least-squares affine map a -> b, normalised by b's inter-ocular distance. */
    static double geomResidual(float[][] a, float[][] b) {
        int n = a.length;
        // Normal equations for [x y 1] * P = target, solved separately for target x and y (3x3 each).
        double[][] ata = new double[3][3];
        double[] atx = new double[3], aty = new double[3];
        for (int i = 0; i < n; i++) {
            double[] row = {a[i][0], a[i][1], 1};
            for (int r = 0; r < 3; r++) {
                for (int c = 0; c < 3; c++) {
                    ata[r][c] += row[r] * row[c];
                }
                atx[r] += row[r] * b[i][0];
                aty[r] += row[r] * b[i][1];
            }
        }
        double[] px = solve(ata, atx), py = solve(ata, aty);
        if (px == null || py == null) {
            return Double.POSITIVE_INFINITY;   // degenerate landmarks: never "static" by accident
        }
        double ss = 0;
        for (int i = 0; i < n; i++) {
            double fx = px[0] * a[i][0] + px[1] * a[i][1] + px[2];
            double fy = py[0] * a[i][0] + py[1] * a[i][1] + py[2];
            ss += (fx - b[i][0]) * (fx - b[i][0]) + (fy - b[i][1]) * (fy - b[i][1]);
        }
        double iod = Math.hypot(b[1][0] - b[0][0], b[1][1] - b[0][1]);
        return iod < 1e-3 ? Double.POSITIVE_INFINITY : Math.sqrt(ss / n) / iod;
    }

    /**
     * Localised photometric residual after intensity-based registration: both crops are standardised (zero mean, unit
     * variance), crop {@code b} is registered onto {@code a} with an affine Lucas-Kanade (Gauss-Newton, forward
     * additive) starting from the landmark alignment, and the result is the maximum over 8x8 blocks of the mean absolute
     * residual inside a 6-pixel border. A still image under re-encoding and global transforms registers down to the
     * JPEG/noise floor; blinks or mouth movement leave a localised residual that the block maximum keeps.
     */
    static double photoResidual(float[] a, float[] b) {
        double[] za = zscore(a), zb = zscore(b);
        if (za == null || zb == null || za.length != zb.length) {
            return Double.POSITIVE_INFINITY;
        }
        int n = (int) Math.round(Math.sqrt(za.length));
        if (n * n != za.length) {
            return Double.POSITIVE_INFINITY;
        }
        double[] p = register(za, zb, n);
        double[] bw = warp(zb, n, p);
        int border = 6, block = 8;
        double best = 0;
        for (int by = border; by + block <= n - border; by += block / 2) {
            for (int bx = border; bx + block <= n - border; bx += block / 2) {
                double s = 0;
                for (int y = by; y < by + block; y++) {
                    for (int x = bx; x < bx + block; x++) {
                        s += Math.abs(za[y * n + x] - bw[y * n + x]);
                    }
                }
                best = Math.max(best, s / (block * block));
            }
        }
        return best;
    }

    /** Affine params p (x' = (1+p0)x + p2 y + p4, y' = p1 x + (1+p3) y + p5) registering b onto a. */
    static double[] register(double[] a, double[] b, int n) {
        double[] p = new double[6];
        int border = 4;
        for (int it = 0; it < 30; it++) {
            double[] bw = warp(b, n, p);
            double[][] h = new double[6][6];
            double[] g = new double[6];
            for (int y = border; y < n - border; y++) {
                for (int x = border; x < n - border; x++) {
                    int i = y * n + x;
                    double gx = (bw[i + 1] - bw[i - 1]) / 2, gy = (bw[i + n] - bw[i - n]) / 2;
                    double[] j = {gx * x, gy * x, gx * y, gy * y, gx, gy};
                    double e = a[i] - bw[i];
                    for (int r = 0; r < 6; r++) {
                        g[r] += j[r] * e;
                        for (int c = 0; c < 6; c++) {
                            h[r][c] += j[r] * j[c];
                        }
                    }
                }
            }
            double[] dp = solve(h, g);
            if (dp == null) {
                break;
            }
            double step = 0;
            for (int k = 0; k < 6; k++) {
                p[k] += dp[k];
                step += Math.abs(dp[k]);
            }
            if (step < 1e-4) {
                break;
            }
        }
        return p;
    }

    /** Bilinear resampling of b at the affine-warped coordinates (edge clamp). */
    static double[] warp(double[] b, int n, double[] p) {
        double[] out = new double[n * n];
        for (int y = 0; y < n; y++) {
            for (int x = 0; x < n; x++) {
                double sx = (1 + p[0]) * x + p[2] * y + p[4];
                double sy = p[1] * x + (1 + p[3]) * y + p[5];
                int x0 = (int) Math.floor(sx), y0 = (int) Math.floor(sy);
                double wx = sx - x0, wy = sy - y0;
                double v00 = at(b, n, x0, y0), v01 = at(b, n, x0 + 1, y0), v10 = at(b, n, x0, y0 + 1), v11 = at(b, n, x0 + 1, y0 + 1);
                out[y * n + x] = (v00 * (1 - wx) + v01 * wx) * (1 - wy) + (v10 * (1 - wx) + v11 * wx) * wy;
            }
        }
        return out;
    }

    private static double at(double[] b, int n, int x, int y) {
        x = x < 0 ? 0 : (x >= n ? n - 1 : x);
        y = y < 0 ? 0 : (y >= n ? n - 1 : y);
        return b[y * n + x];
    }

    /** Gaussian elimination with partial pivoting; null if singular. */
    static double[] solve(double[][] m, double[] y) {
        int k = y.length;
        double[][] a = new double[k][k + 1];
        for (int r = 0; r < k; r++) {
            System.arraycopy(m[r], 0, a[r], 0, k);
            a[r][k] = y[r];
        }
        for (int c = 0; c < k; c++) {
            int piv = c;
            for (int r = c + 1; r < k; r++) {
                if (Math.abs(a[r][c]) > Math.abs(a[piv][c])) {
                    piv = r;
                }
            }
            if (Math.abs(a[piv][c]) < 1e-12) {
                return null;
            }
            double[] t = a[c];
            a[c] = a[piv];
            a[piv] = t;
            for (int r = 0; r < k; r++) {
                if (r != c) {
                    double f = a[r][c] / a[c][c];
                    for (int q = c; q <= k; q++) {
                        a[r][q] -= f * a[c][q];
                    }
                }
            }
        }
        double[] out = new double[k];
        for (int r = 0; r < k; r++) {
            out[r] = a[r][k] / a[r][r];
        }
        return out;
    }

    private static double[] zscore(float[] v) {
        double m = 0;
        for (float x : v) {
            m += x;
        }
        m /= v.length;
        double var = 0;
        for (float x : v) {
            var += (x - m) * (x - m);
        }
        double sd = Math.sqrt(var / v.length);
        if (sd < 1e-6) {
            return null;
        }
        double[] z = new double[v.length];
        for (int i = 0; i < v.length; i++) {
            z[i] = (v[i] - m) / sd;
        }
        return z;
    }
}
