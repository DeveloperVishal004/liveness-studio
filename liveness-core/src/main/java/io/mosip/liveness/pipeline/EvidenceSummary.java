package io.mosip.liveness.pipeline;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Aggregate, non-biometric description of per-frame evidence (counts, distributions; no images, no embeddings). */
public final class EvidenceSummary {
    private EvidenceSummary() {}

    public static Map<String, Object> of(List<FramePipeline.FrameEvidence> list) {
        List<FramePipeline.FrameEvidence> ev;
        synchronized (list) {
            ev = new ArrayList<>(list);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        Map<String, Integer> reasons = new TreeMap<>();
        List<Float> pads = new ArrayList<>();
        List<Float> faceH = new ArrayList<>();
        List<Double> sharp = new ArrayList<>();
        List<Double> grey = new ArrayList<>();
        int eligible = 0;
        int detectorRuns = 0;
        int embeddings = 0;
        for (FramePipeline.FrameEvidence e : ev) {
            if (e.detectorRan) {
                detectorRuns++;
            }
            if (e.eligible) {
                eligible++;
                pads.add(e.padFused);
            } else {
                reasons.merge(e.ineligibleReason, 1, Integer::sum);
            }
            if (e.faceCount == 1) {
                faceH.add(e.faceHeightPx);
                sharp.add(e.sharpness);
                grey.add(e.meanGrey);
            }
            if (e.embedding != null) {
                embeddings++;
            }
        }
        m.put("frames", ev.size());
        m.put("eligible", eligible);
        m.put("eligible_ratio", ev.isEmpty() ? 0 : LatencyStats.round((double) eligible / ev.size()));
        m.put("detector_runs", detectorRuns);
        m.put("ineligible_reasons", reasons);
        m.put("face_height_px", quantiles(faceH));
        m.put("face_sharpness_lapvar", quantiles(sharp));
        m.put("face_mean_grey", quantiles(grey));
        m.put("pad_p_real_DIAGNOSTIC_ONLY", quantiles(pads));
        m.put("embeddings", embeddings);
        return m;
    }

    static <T extends Number> Map<String, Object> quantiles(List<T> v) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (v.isEmpty()) {
            m.put("n", 0);
            return m;
        }
        List<Double> d = new ArrayList<>();
        for (T x : v) {
            d.add(x.doubleValue());
        }
        Collections.sort(d);
        m.put("n", d.size());
        m.put("p5", r(d.get((int) (0.05 * (d.size() - 1)))));
        m.put("p50", r(d.get((d.size() - 1) / 2)));
        m.put("p95", r(d.get((int) (0.95 * (d.size() - 1)))));
        return m;
    }

    private static double r(double x) {
        return Math.round(x * 1000.0) / 1000.0;
    }
}
