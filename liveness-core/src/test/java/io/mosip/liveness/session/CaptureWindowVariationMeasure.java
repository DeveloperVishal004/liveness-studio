package io.mosip.liveness.session;

import io.mosip.liveness.vision.Phase0Models;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * [SIM] cost estimate of the PROPOSED capture-window variation rule: for every capture-length window (frames arriving
 * after t_req + 300 ms until the response of a 1.5 s capture ≈ 22 frames at 15 fps) inside the 30-frame temporal fixtures, does the window contain a varying
 * pair? Synthetic motion (blink every 2.5 s) is not human motion; this does not estimate a real false-reject rate.
 * Prints only. Run explicitly: mvn test -Dtest=CaptureWindowVariationMeasure
 */
class CaptureWindowVariationMeasure {
    @Test
    void printWindowVariationRates() throws Exception {
        SessionPolicy p = new SessionPolicy();
        StaticReplayDetector det = new StaticReplayDetector(p.staticPhotoThreshold, p.captureWindowMinPairs, p.staticMinVaryingPairs);
        int win = 22;
        try (Phase0Models m = Phase0Models.load(TemporalFixtures.root(), 1, 320, false)) {
            for (String kind : new String[] {"animate", "static_replay"}) {
                int varying = 0, total = 0;
                for (String src : new String[] {"T1", "lfwA", "lfwB", "lfwC", "hoD", "hoE", "hoF"}) {
                    List<EvidenceRecord> rs = TemporalFixtures.records(m, kind, src);
                    for (int start = 0; start + win <= rs.size(); start++) {
                        List<EvidenceRecord> w = new ArrayList<>();
                        for (EvidenceRecord r : rs.subList(start, start + win)) {
                            if (r.eligible) {
                                w.add(r);
                            }
                        }
                        total++;
                        if (det.assess(w).verdict == StaticReplayDetector.Verdict.VARYING) {
                            varying++;
                        }
                    }
                }
                System.out.printf("CAPTURE-WINDOW %s: %d/%d windows VARYING%n", kind, varying, total);
            }
        }
    }
}
