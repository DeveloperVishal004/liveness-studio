package io.mosip.liveness.pipeline;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Exact percentile recorder for benchmark runs (stores every sample; fine for <= millions of samples). */
public final class LatencyStats {
    private long[] samples = new long[1024];
    private int n;

    public synchronized void record(long nanos) {
        if (n == samples.length) {
            samples = Arrays.copyOf(samples, n * 2);
        }
        samples[n++] = nanos;
    }

    public synchronized int count() { return n; }

    /** Nearest-rank percentile in milliseconds; NaN when empty. */
    public synchronized double percentileMs(double p) {
        if (n == 0) {
            return Double.NaN;
        }
        long[] s = Arrays.copyOf(samples, n);
        Arrays.sort(s);
        int idx = (int) Math.ceil(p / 100.0 * n) - 1;
        return s[Math.max(0, Math.min(n - 1, idx))] / 1e6;
    }

    public synchronized double meanMs() {
        if (n == 0) {
            return Double.NaN;
        }
        double t = 0;
        for (int i = 0; i < n; i++) {
            t += samples[i];
        }
        return t / n / 1e6;
    }

    public Map<String, Object> summary() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("n", count());
        m.put("mean_ms", round(meanMs()));
        m.put("p50_ms", round(percentileMs(50)));
        m.put("p95_ms", round(percentileMs(95)));
        m.put("p99_ms", round(percentileMs(99)));
        m.put("max_ms", round(percentileMs(100)));
        return m;
    }

    static double round(double v) {
        return Double.isNaN(v) ? v : Math.round(v * 100.0) / 100.0;
    }
}
