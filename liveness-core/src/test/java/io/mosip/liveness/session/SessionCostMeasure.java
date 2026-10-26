package io.mosip.liveness.session;

import io.mosip.liveness.session.SessionHarness.Kind;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * [M1] cost of one onEvidence() call (held under the session lock) with a full 5 s window of eligible frames.
 * Print-only. Run: mvn test -Dtest=SessionCostMeasure
 */
class SessionCostMeasure {
    @Test
    void printPerFrameCost() {
        SessionPolicy p = new SessionPolicy();
        p.streamAccept = 0.99f;                         // keep the session in CAPTURING so every frame runs the full passive rule
        SessionHarness h = new SessionHarness(p, new AttemptLedger.InMemory(), new SessionHarness.StubVerifier(), null);
        h.session.start();
        h.frames(80, Kind.LIVE);                        // fill the 5 s static window
        int n = 300;
        long[] t = new long[n];
        for (int i = 0; i < n; i++) {
            long a = System.nanoTime();
            h.frames(1, Kind.LIVE);
            t[i] = System.nanoTime() - a;
            if (h.session.state() != SessionOutcome.State.CAPTURING) {
                h.session.retry();
            }
        }
        Arrays.sort(t);
        System.out.printf("SESSION-COST [M1] onEvidence+embedding per frame: p50=%.2f ms p95=%.2f ms max=%.2f ms (frame interval 66.7 ms)%n",
                t[n / 2] / 1e6, t[(int) (n * 0.95)] / 1e6, t[n - 1] / 1e6);
    }
}
