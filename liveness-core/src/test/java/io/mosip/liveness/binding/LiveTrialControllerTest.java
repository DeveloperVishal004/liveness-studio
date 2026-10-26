package io.mosip.liveness.binding;

import io.mosip.liveness.live.LiveTrialController;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionPolicy;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Webcam trial controller through the REAL pipeline/models/session/binder: frames are fed at 15 fps exactly as the
 * stream reader feeds them; the RCAPTURE is a real RS256-signed response (TEST keys). The decision shown must be the
 * session outcome, whatever the input. Capture PAD is pinned in some tests so the capture step is deterministic
 * (PAD accuracy is not under test). [CODE]; no camera, no real-device claim.
 */
class LiveTrialControllerTest {
    @BeforeAll
    static void load() throws Exception {
        LivenessClientAdapterTest.load();
    }

    @AfterAll
    static void close() throws Exception {
        LivenessClientAdapterTest.close();
    }

    static List<byte[]> frames(String kind) throws Exception {
        Path root = Paths.get(System.getProperty("phase0.root", "..")).toAbsolutePath().normalize();
        List<byte[]> out = new ArrayList<>();
        try (Stream<Path> s = Files.list(root.resolve("research/fixtures/temporal/" + kind + "/T1"))) {
            for (Path p : s.filter(x -> x.toString().endsWith(".jpg")).sorted().collect(Collectors.toList())) {
                out.add(Files.readAllBytes(p));
            }
        }
        return out;
    }

    static LiveTrialController controller(CaptureAnalyzer analyzer, LiveTrialController.CaptureFunction capture) {
        CaptureBinder binder = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier, analyzer, new CaptureBinder.Policy());
        FramePipeline.Config cfg = new FramePipeline.Config();
        cfg.embedEvery = 3;
        return new LiveTrialController(LivenessClientAdapterTest.models, cfg, new SessionPolicy(), binder,
                new LivenessSession.DeviceIdentity(CaptureBinderTest.SERIAL, "Phase0", "MOCK-FACE-1", "L0"), capture);
    }

    /** A signed RCAPTURE echoing the request nonce, capture image = a fixture frame. */
    static LiveTrialController.CaptureFunction signedCapture() {
        return txn -> {
            Thread.sleep(300);
            byte[] img = LivenessClientAdapterTest.frames.get(15);
            return CaptureBinderTest.response(c -> {
                c.txn = txn;
                c.ts = Instant.now().minusMillis(100);
                c.bioValue = CaptureBinderTest.iso(img, 640, 480, 0);
            });
        };
    }

    /** Feeds frames (looping, distinct bytes) at 15 fps until the trial finishes; returns the final status. */
    static LiveTrialController.Status runTrial(LiveTrialController c, List<byte[]> frames) throws Exception {
        return runTrial(c, frames, null);
    }

    static LiveTrialController.Status runTrial(LiveTrialController c, List<byte[]> frames, String label) throws Exception {
        c.startTrial(label);
        long t0 = System.currentTimeMillis();
        int n = 0;
        LiveTrialController.Status s = c.poll();
        while (s.trialActive && System.currentTimeMillis() - t0 < 25_000) {
            c.onStreamFrame(LivenessClientAdapterTest.withTrailer(frames.get(n % frames.size()), n));
            n++;
            Thread.sleep(66);
            s = c.poll();
        }
        return s;
    }

    @Test
    void decisionIsTheSessionOutcomeOnTheFullRealPath() throws Exception {
        try (LiveTrialController c = controller(LivenessClientAdapterTest.pinnedPad(), signedCapture())) {
            LiveTrialController.Status s = runTrial(c, frames("animate"));
            assertEquals("VERIFIED", s.state, s.verdict + " / " + s.detail);
            assertTrue(s.verdict.startsWith("VERIFIED by the engine"));
            assertTrue(s.captureIssued);
            assertTrue(s.medianPad != null && s.capturePad != null && s.bindMs != null, "transparency fields populated");
            assertEquals(1, c.history().size());
        }
    }

    @Test
    void faceDetectedIsNeverEnoughAStaticPhotoIsNotVerified() throws Exception {
        try (LiveTrialController c = controller(LivenessClientAdapterTest.pinnedPad(), signedCapture())) {
            LiveTrialController.Status s = runTrial(c, frames("static_replay"));
            assertEquals(1, s.faceCount, "a face WAS detected");
            assertFalse("VERIFIED".equals(s.state), s.verdict);
            assertFalse(s.verdict.contains("VERIFIED"), s.verdict);
            assertFalse(s.captureIssued, "the session never became ready, so no capture was requested");
            assertEquals("STATIC_REPLAY_SUSPECT", s.reason);
        }
    }

    /** The operator label is recorded only: a mislabelled trial gets exactly the decision its frames earn. */
    @Test
    void labelIsRecordedButNeverChangesTheDecision() throws Exception {
        try (LiveTrialController c = controller(LivenessClientAdapterTest.pinnedPad(), signedCapture())) {
            LiveTrialController.Status liveFramesLabelledPhoto = runTrial(c, frames("animate"), "photo");
            assertEquals("VERIFIED", liveFramesLabelledPhoto.state, liveFramesLabelledPhoto.verdict);
            assertEquals("photo", liveFramesLabelledPhoto.label);
            LiveTrialController.Status stillFramesLabelledLive = runTrial(c, frames("static_replay"), "live");
            assertEquals("STATIC_REPLAY_SUSPECT", stillFramesLabelledLive.reason, stillFramesLabelledLive.verdict);
            assertEquals("live", stillFramesLabelledLive.label);
            assertEquals(java.util.Arrays.asList("photo", "live"),
                    c.history().stream().map(h -> h.label).collect(Collectors.toList()));
        }
    }

    /** A trial abandoned mid-way (new trial started, or window closed) stays in the history, marked unfinished. */
    @Test
    void abandonedTrialsAreKeptAsUnfinished() throws Exception {
        try (LiveTrialController c = controller(LivenessClientAdapterTest.pinnedPad(), signedCapture())) {
            c.startTrial("video");
            c.poll();
            c.startTrial("photo");
            c.poll();
            c.close();
            List<LiveTrialController.Status> h = c.history();
            assertEquals(2, h.size());
            for (LiveTrialController.Status s : h) {
                assertTrue(s.unfinished, s.label);
                assertFalse(s.trialActive);
                assertFalse("VERIFIED".equals(s.state));
            }
            assertEquals("video", h.get(0).label);
            assertEquals("photo", h.get(1).label);
        }
    }

    @Test
    void lowCapturePadIsRejectedOnTheSamePath() throws Exception {
        CaptureAnalyzer low = img -> {
            CaptureAnalyzer.Analysis a = new VisionCaptureAnalyzer(LivenessClientAdapterTest.models).analyze(img);
            return new CaptureAnalyzer.Analysis(a.faceCount, 0.05f, a.embedding);   // e.g. a screen replay at capture
        };
        try (LiveTrialController c = controller(low, signedCapture())) {
            LiveTrialController.Status s = runTrial(c, frames("animate"));
            assertEquals("REJECTED_ATTACK", s.state, s.verdict);
            assertEquals("CAPTURE_PAD_ATTACK", s.reason);
        }
    }

    /**
     * Regression (webcam window hung at the end of a trial): frames arrive on their own thread, as from the real
     * stream reader, so the worker is usually inside the observer callback when poll() ends the trial. poll() must
     * never close the adapter while holding the lock that callback needs. The hook pauses while that lock is held as
     * the trial ends, so the worker is certainly blocked in the callback: deterministic without the fix.
     */
    @Test
    @org.junit.jupiter.api.Timeout(value = 90, threadMode = org.junit.jupiter.api.Timeout.ThreadMode.SEPARATE_THREAD)  // fail, never hang
    void endingATrialWhileFramesKeepArrivingDoesNotDeadlock() throws Exception {
        try (LiveTrialController c = controller(LivenessClientAdapterTest.pinnedPad(), signedCapture())) {
            List<byte[]> f = frames("static_replay");             // ends without a capture (fastest finish)
            java.util.concurrent.atomic.AtomicBoolean feeding = new java.util.concurrent.atomic.AtomicBoolean(true);
            Thread feeder = new Thread(() -> {
                int n = 0;
                while (feeding.get()) {
                    c.onStreamFrame(LivenessClientAdapterTest.withTrailer(f.get(n % f.size()), n));
                    n++;
                    if (n % 4 == 0) {
                        Thread.yield();
                    }
                }
            }, "test-stream");
            feeder.setDaemon(true);
            java.util.concurrent.ExecutorService ui = java.util.concurrent.Executors.newSingleThreadExecutor();
            io.mosip.liveness.live.LiveTestHooks.onTrialFinishing(() -> {
                try {
                    Thread.sleep(300);                            // several frame times: the worker reaches the callback
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            try {
                c.startTrial();
                feeder.start();
                long t0 = System.currentTimeMillis();
                LiveTrialController.Status s;
                do {
                    s = ui.submit(c::poll).get(5, java.util.concurrent.TimeUnit.SECONDS);   // a hang fails here
                    Thread.sleep(33);
                } while (s.trialActive && System.currentTimeMillis() - t0 < 25_000);
                assertFalse(s.trialActive, "trial finished: " + s.verdict);
                // the window keeps polling and the user starts another trial while frames still arrive
                ui.submit(c::poll).get(5, java.util.concurrent.TimeUnit.SECONDS);
                ui.submit(() -> c.startTrial()).get(5, java.util.concurrent.TimeUnit.SECONDS);
                assertTrue(ui.submit(c::poll).get(5, java.util.concurrent.TimeUnit.SECONDS).trialActive);
            } finally {
                io.mosip.liveness.live.LiveTestHooks.onTrialFinishing(null);
                feeding.set(false);
                feeder.join(5_000);
                ui.shutdownNow();
            }
        }
    }

    @Test
    void failingRcaptureIsNeverVerified() throws Exception {
        try (LiveTrialController c = controller(LivenessClientAdapterTest.pinnedPad(), txn -> { throw new java.io.IOException("device unplugged"); })) {
            c.startTrial();
            LiveTrialController.Status s = c.poll();
            List<byte[]> f = frames("animate");
            long t0 = System.currentTimeMillis();
            int n = 0;
            while (!s.captureIssued && System.currentTimeMillis() - t0 < 15_000) {
                c.onStreamFrame(LivenessClientAdapterTest.withTrailer(f.get(n % f.size()), n));
                n++;
                Thread.sleep(66);
                s = c.poll();
            }
            Thread.sleep(300);
            s = c.poll();
            assertFalse("VERIFIED".equals(s.state), s.verdict);
            assertTrue(s.detail != null && s.detail.contains("RCAPTURE failed"), String.valueOf(s.detail));
        }
    }
}
