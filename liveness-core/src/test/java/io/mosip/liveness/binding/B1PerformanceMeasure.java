package io.mosip.liveness.binding;

import io.mosip.liveness.streamauth.StreamAuthResult;
import io.mosip.liveness.streamauth.StreamAuthenticator;
import io.mosip.liveness.streamauth.StreamDigest;
import io.mosip.liveness.streamauth.StreamDigestVerifier;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * [M1] PERFORMANCE PROXIES for the B1 prototype on this laptop (not the reference host, not an L1 device):
 * client SHA-256 per received frame, statement size and client verification time for 450 entries (≈ 30 s at 15 fps).
 * Device-side signing cost on real hardware is NOT measured here. Prints only. Run: mvn test -Dtest=B1PerformanceMeasure
 */
class B1PerformanceMeasure {
    @Test
    void printProxies() throws Exception {
        CaptureBinderTest.keys();
        Path frameFile = Paths.get(System.getProperty("phase0.root", "..")).resolve("research/fixtures/temporal/animate/T1/f000.jpg");
        byte[] frame = Files.readAllBytes(frameFile);
        for (int i = 0; i < 2000; i++) {
            StreamDigest.sha256(frame);                            // warm-up
        }
        int n = 5000;
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            StreamDigest.sha256(frame);
        }
        double hashUs = (System.nanoTime() - t0) / 1e3 / n;

        int entries = 450;
        B1Fixture fx = new B1Fixture("txn-1");
        List<StreamAuthenticator.FrameRef> refs = new ArrayList<>();
        long tStart = Instant.now().toEpochMilli() - 30_000;
        for (int i = 0; i < entries; i++) {
            byte[] b = B1Fixture.frameBytes(i);
            fx.emit(b, tStart + i * 67L);
            refs.add(new StreamAuthenticator.FrameRef(i, StreamDigest.sha256(b), true, i >= entries - 25));
        }
        byte[] resp = fx.attach(CaptureBinderTest.response(c -> c.txn = "txn-1"));
        int statementBytes = CaptureBinderTest.JSON.readTree(resp).path("biometrics").path(0).path("additionalInfo").path(StreamDigest.ADDITIONAL_INFO_KEY).asText().length();
        StreamDigestVerifier v = new StreamDigestVerifier(CaptureBinderTest.verifier);
        Instant now = Instant.now();
        StreamAuthenticator.Context ctx = new StreamAuthenticator.Context("txn-1", CaptureBinderTest.SERIAL,
                now.minusSeconds(2), now.plusSeconds(1), refs, 2, 2, 5_000);
        StreamAuthResult r = null;
        for (int i = 0; i < 50; i++) {
            r = v.verify(resp, ctx, now);
        }
        int m = 200;
        long[] ts = new long[m];
        for (int i = 0; i < m; i++) {
            long a = System.nanoTime();
            r = v.verify(resp, ctx, now);
            ts[i] = System.nanoTime() - a;
        }
        Arrays.sort(ts);
        System.out.printf("B1-PROXY [M1] frame=%d bytes sha256=%.1f us/frame (%.2f%% of a 66.7 ms frame interval)%n",
                frame.length, hashUs, hashUs / 66_700 * 100);
        System.out.printf("B1-PROXY [M1] statement entries=%d jws_chars=%d verify p50=%.2f ms p95=%.2f ms result=%s%n",
                entries, statementBytes, ts[m / 2] / 1e6, ts[(int) (m * 0.95)] / 1e6, r);
    }
}
