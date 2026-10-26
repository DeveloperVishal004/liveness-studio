package io.mosip.liveness.binding;

import io.mosip.liveness.integration.LivenessClientAdapter;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionClock;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionPolicy;
import io.mosip.liveness.streamauth.StreamDigestVerifier;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * [M1] MICROBENCHMARK of the capture critical section: real CaptureBinder (RS256, ISO + JPEG 2000 decode, YuNet/PAD/SFace
 * on the capture), B1 verification, real pipeline via LivenessClientAdapter. A streamer thread tags a frame every 20 ms;
 * we record how long each tag call blocks while onCaptureResponse runs (= receipt-timestamp staleness) and the response
 * duration. Not an end-to-end real-time claim. Prints only. Run: mvn test -Dtest=CaptureLockMeasure
 */
class CaptureLockMeasure {
    @Test
    void printCaptureCriticalSection() throws Exception {
        LivenessClientAdapterTest.load();
        try {
            byte[] jp2 = Files.readAllBytes(Paths.get(System.getProperty("phase0.root", "..")).resolve("research/fixtures/capture/T1_f015_640x480.jp2"));
            List<Double> tagBlockedMs = Collections.synchronizedList(new ArrayList<>());
            List<Double> lockWaitMs = Collections.synchronizedList(new ArrayList<>());
            List<Double> respMs = new ArrayList<>();
            for (int run = 0; run < 6; run++) {
                SessionPolicy p = new SessionPolicy();
                p.requireStreamAuthentication = true;
                CaptureBinder binder = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier,
                        LivenessClientAdapterTest.pinnedPad(), new CaptureBinder.Policy());   // full path incl. B1
                LivenessSession s = new LivenessSession(p, SessionClock.SYSTEM, binder, new AttemptLedger.InMemory(), "m" + run,
                        new LivenessSession.DeviceIdentity(CaptureBinderTest.SERIAL, "Phase0", "MOCK-FACE-1", "L0"),
                        new StreamDigestVerifier(CaptureBinderTest.verifier));
                s.start();
                FramePipeline.Config cfg = new FramePipeline.Config();
                cfg.embedEvery = 3;
                LivenessClientAdapter ad = new LivenessClientAdapter(s, LivenessClientAdapterTest.models, cfg);
                List<byte[]> emitted = Collections.synchronizedList(new ArrayList<>());
                AtomicBoolean stop = new AtomicBoolean();
                List<long[]> tagCalls = Collections.synchronizedList(new ArrayList<>());      // {start, end} ns
                List<long[]> lockProbes = Collections.synchronizedList(new ArrayList<>());
                Thread streamer = new Thread(() -> {
                    int n = 0;
                    while (!stop.get()) {
                        byte[] f = LivenessClientAdapterTest.withTrailer(LivenessClientAdapterTest.frames.get(n % LivenessClientAdapterTest.frames.size()), n);
                        emitted.add(f);
                        long a = System.nanoTime();
                        ad.onStreamFrame(f);
                        tagCalls.add(new long[] {a, System.nanoTime()});
                        n++;
                        try {
                            Thread.sleep(20);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }
                });
                streamer.setDaemon(true);
                streamer.start();
                Thread prober = new Thread(() -> {                     // lock-acquisition latency, side-effect free
                    while (!stop.get()) {
                        long a = System.nanoTime();
                        s.outcome();
                        lockProbes.add(new long[] {a, System.nanoTime()});
                        try {
                            Thread.sleep(1);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }
                });
                prober.setDaemon(true);
                prober.start();
                long t0 = System.currentTimeMillis();
                while (s.state() != SessionOutcome.State.READY_FOR_CAPTURE && System.currentTimeMillis() - t0 < 15_000) {
                    Thread.sleep(20);
                }
                LivenessSession.CaptureRequest req = ad.beginCapture();
                Thread.sleep(300);
                byte[] resp = CaptureBinderTest.response(c -> {
                    c.txn = req.transactionId;
                    c.ts = Instant.now().minusMillis(100);
                    c.bioValue = CaptureBinderTest.iso(jp2, 640, 480, 1);
                });
                B1Fixture fx = new B1Fixture(req.transactionId);
                long now = System.currentTimeMillis();
                synchronized (emitted) {
                    for (int i = 0; i < emitted.size(); i++) {
                        fx.emit(emitted.get(i), now - (emitted.size() - 1 - i) * 20L);
                    }
                }
                fx.issuedAt = Instant.now();
                byte[] full = fx.attach(resp);
                long a = System.nanoTime();
                SessionOutcome o = ad.onCaptureResponse(req.transactionId, full);
                long b = System.nanoTime();
                respMs.add((b - a) / 1e6);
                Thread.sleep(60);
                stop.set(true);
                streamer.join();
                prober.join();
                synchronized (tagCalls) {
                    for (long[] c : tagCalls) {
                        if (c[0] >= a && c[0] <= b) {
                            tagBlockedMs.add((c[1] - c[0]) / 1e6);
                        }
                    }
                }
                synchronized (lockProbes) {
                    for (long[] c : lockProbes) {
                        if (c[0] >= a && c[0] <= b) {
                            lockWaitMs.add((c[1] - c[0]) / 1e6);
                        }
                    }
                }
                ad.close();
                System.out.println("CAPTURE-LOCK run " + run + " outcome " + o.state + "/" + o.reason + " b1=" + o.streamAuthResult);
            }
            List<Double> t = new ArrayList<>(tagBlockedMs);
            Collections.sort(t);
            List<Double> lw = new ArrayList<>(lockWaitMs);
            Collections.sort(lw);
            System.out.printf("CAPTURE-LOCK [M1] lock-acquisition latency during response processing (1 ms probe): n=%d median %.2f ms, p95 %.2f ms, max %.2f ms%n",
                    lw.size(), lw.get(lw.size() / 2), lw.get((int) (lw.size() * 0.95)), lw.get(lw.size() - 1));
            Collections.sort(respMs);
            System.out.printf("CAPTURE-LOCK [M1] onCaptureResponse: median %.1f ms, max %.1f ms (n=%d)%n",
                    respMs.get(respMs.size() / 2), respMs.get(respMs.size() - 1), respMs.size());
            System.out.printf("CAPTURE-LOCK [M1] stream-thread tag call during response processing: n=%d median %.2f ms, p95 %.2f ms, max %.2f ms%n",
                    t.size(), t.get(t.size() / 2), t.get((int) (t.size() * 0.95)), t.get(t.size() - 1));
        } finally {
            LivenessClientAdapterTest.close();
        }
    }
}
