package io.mosip.liveness.session;

import io.mosip.liveness.vision.Phase0Models;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Prints per-pair residual distributions on the [SIM] temporal fixtures. Used once to choose provisional thresholds;
 * it asserts nothing. Run explicitly: mvn test -Dtest=StaticReplayCalibrationMeasure
 */
class StaticReplayCalibrationMeasure {

    @Test
    void printResidualDistributions() throws Exception {
        try (Phase0Models m = Phase0Models.load(TemporalFixtures.root(), 1, 320, false)) {
            for (String kind : new String[] {"static_replay", "animate"}) {
                for (String src : new String[] {"T1", "lfwA", "lfwB", "lfwC"}) {
                    List<EvidenceRecord> rs = TemporalFixtures.records(m, kind, src);
                    List<Double> g = new ArrayList<>(), p = new ArrayList<>();
                    EvidenceRecord prev = null;
                    int eligible = 0;
                    for (EvidenceRecord r : rs) {
                        if (r.alignedGrey == null) {
                            continue;
                        }
                        eligible++;
                        if (prev != null) {
                            g.add(StaticReplayDetector.geomResidual(prev.landmarks, r.landmarks));
                            p.add(StaticReplayDetector.photoResidual(prev.alignedGrey, r.alignedGrey));
                        }
                        prev = r;
                    }
                    System.out.printf("CALIB %-13s %-5s eligible=%d geom[p50=%.4f p90=%.4f max=%.4f] photo[min=%.4f p50=%.4f p90=%.4f max=%.4f]%n",
                            kind, src, eligible, q(g, .5), q(g, .9), q(g, 1), q(p, 0), q(p, .5), q(p, .9), q(p, 1));
                    List<EvidenceRecord> el = new ArrayList<>();
                    for (EvidenceRecord r : rs) {
                        if (r.alignedGrey != null) {
                            el.add(r);
                        }
                    }
                    for (int lag : new int[] {3, 6}) {
                        List<Double> pl = new ArrayList<>();
                        for (int i = lag; i < el.size(); i++) {
                            pl.add(StaticReplayDetector.photoResidual(el.get(i - lag).alignedGrey, el.get(i).alignedGrey));
                        }
                        System.out.printf("CALIB-LAG%d %-13s %-5s photo[p10=%.4f p50=%.4f p90=%.4f max=%.4f]%n", lag, kind, src,
                                q(pl, .1), q(pl, .5), q(pl, .9), q(pl, 1));
                    }
                }
            }
        }
    }

    static double q(List<Double> v, double p) {
        if (v.isEmpty()) {
            return Double.NaN;
        }
        List<Double> s = new ArrayList<>(v);
        Collections.sort(s);
        return s.get((int) Math.round(p * (s.size() - 1)));
    }
}
