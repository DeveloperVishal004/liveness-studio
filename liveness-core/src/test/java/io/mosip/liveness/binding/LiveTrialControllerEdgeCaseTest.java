package io.mosip.liveness.binding;

import io.mosip.liveness.live.LiveTrialController;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The webcam controller under abuse, through the real pipeline: garbage and hostile frames, rapid restarts, a flood and
 * a frozen feed. The decision must never be VERIFIED from bad input, nothing may throw into the stream thread, and the
 * controller must stay usable. [CODE]; no camera.
 */
class LiveTrialControllerEdgeCaseTest {
    @BeforeAll
    static void load() throws Exception {
        LivenessClientAdapterTest.load();
    }

    @AfterAll
    static void close() throws Exception {
        LivenessClientAdapterTest.close();
    }

    static LiveTrialController controller() {
        return LiveTrialControllerTest.controller(LivenessClientAdapterTest.pinnedPad(), LiveTrialControllerTest.signedCapture());
    }

    private static long workers() {
        return Thread.getAllStackTraces().keySet().stream().filter(t -> t.isAlive() && "liveness-worker".equals(t.getName())).count();
    }

    @Test
    void usingTheControllerBeforeAnyTrialOrAfterCloseIsHarmless() {
        LiveTrialController c = controller();
        LiveTrialController.Status s = assertDoesNotThrow(c::poll);
        assertEquals(0, s.trial);
        assertEquals("IDLE", s.state);
        assertFalse(s.trialActive);
        assertDoesNotThrow(() -> c.onStreamFrame(new byte[] {1, 2, 3}));      // no trial: frame is only kept for display
        assertDoesNotThrow(() -> c.onStreamFrame(null));
        assertDoesNotThrow(c::close);
        assertDoesNotThrow(c::close);                                          // idempotent
        assertDoesNotThrow(c::poll);
        assertTrue(c.history().isEmpty());
    }

    @Test
    @Timeout(180)
    void thirtyRapidRestartsKeepEveryAbandonedTrialAndLeakNoWorkerThreads() throws Exception {
        long before = workers();
        try (LiveTrialController c = controller()) {
            List<byte[]> f = LiveTrialControllerTest.frames("animate");
            for (int i = 0; i < 30; i++) {
                c.startTrial(i % 3 == 0 ? "live" : i % 3 == 1 ? "video" : "photo");
                for (int k = 0; k < 3; k++) {
                    c.onStreamFrame(LivenessClientAdapterTest.withTrailer(f.get((i + k) % f.size()), i * 10 + k));
                }
                c.poll();
            }
            assertTrue(workers() - before <= 1, "at most the live trial's worker remains: " + (workers() - before));
            assertEquals(29, c.history().size(), "29 abandoned trials are recorded, none silently dropped");
            for (LiveTrialController.Status h : c.history()) {
                assertTrue(h.unfinished);
                assertFalse("VERIFIED".equals(h.state));
            }
        }
        assertEquals(before, workers(), "closing the controller stops the last worker");
    }

    @Test
    @Timeout(240)
    void garbageHostileAndHugeFramesNeverThrowAndNeverVerifyAndTheNextTrialIsClean() throws Exception {
        Random r = new Random(3);
        byte[] real = LiveTrialControllerTest.frames("animate").get(0);
        byte[] noise = new byte[1 << 20];
        r.nextBytes(noise);
        byte[] truncated = java.util.Arrays.copyOf(real, real.length / 3);
        byte[] soiOnly = {(byte) 0xFF, (byte) 0xD8};
        byte[] soiEoi = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xD9};
        byte[] lying = real.clone();                                           // valid JPEG with its dimension bytes mangled
        for (int i = 0; i < lying.length - 9; i++) {
            if ((lying[i] & 0xFF) == 0xFF && (lying[i + 1] & 0xFF) == 0xC0) {
                lying[i + 5] = (byte) 0xFF;
                lying[i + 6] = (byte) 0xFF;
                lying[i + 7] = (byte) 0xFF;
                lying[i + 8] = (byte) 0xFF;
                break;
            }
        }
        byte[][] hostile = {null, new byte[0], new byte[] {0}, noise, truncated, soiOnly, soiEoi, lying, new byte[50_000_000]};
        try (LiveTrialController c = controller()) {
            c.startTrial("live");
            LiveTrialController.Status s = c.poll();
            for (int i = 0; i < hostile.length; i++) {
                byte[] frame = hostile[i];
                assertDoesNotThrow(() -> c.onStreamFrame(frame), "hostile frame " + i);
                s = assertDoesNotThrow(c::poll);
                assertFalse("VERIFIED".equals(s.state), "hostile frame " + i + ": " + s.verdict);
                assertFalse(s.captureIssued, "no capture may follow garbage, frame " + i);
            }
            Thread.sleep(500);
            s = c.poll();
            assertFalse("VERIFIED".equals(s.state), s.verdict);
            // the controller is not poisoned: a fresh trial on good frames reaches the engine's own decision
            LiveTrialController.Status clean = LiveTrialControllerTest.runTrial(c, LiveTrialControllerTest.frames("animate"), "live");
            assertEquals("VERIFIED", clean.state, clean.verdict + " / " + clean.detail);
        }
    }

    @Test
    @Timeout(120)
    void aFloodOfFramesIsBoundedAndTheControllerStaysResponsive() throws Exception {
        try (LiveTrialController c = controller()) {
            c.startTrial("video");
            List<byte[]> f = LiveTrialControllerTest.frames("animate");
            long t0 = System.nanoTime();
            for (int i = 0; i < 2_000; i++) {                                   // far faster than any camera; the mailbox keeps the newest
                c.onStreamFrame(LivenessClientAdapterTest.withTrailer(f.get(i % f.size()), i));
            }
            long ms = (System.nanoTime() - t0) / 1_000_000L;
            assertTrue(ms < 20_000, "feeding 2000 frames must not block on processing: " + ms + " ms");
            long p0 = System.nanoTime();
            c.poll();
            assertTrue((System.nanoTime() - p0) / 1_000_000L < 2_000, "poll stays responsive under load");
        }
    }

    @Test
    @Timeout(120)
    void aFrozenFeedOfIdenticalBytesIsNeverAcceptedAndNeverGetsACapture() throws Exception {
        try (LiveTrialController c = controller()) {
            c.startTrial("photo");
            byte[] one = LiveTrialControllerTest.frames("animate").get(0);       // the same bytes again and again
            LiveTrialController.Status s = c.poll();
            long t0 = System.currentTimeMillis();
            while (s.trialActive && System.currentTimeMillis() - t0 < 14_000) {
                c.onStreamFrame(one.clone());
                Thread.sleep(66);
                s = c.poll();
            }
            assertFalse("VERIFIED".equals(s.state), s.verdict);
            assertFalse(s.captureIssued, "a frozen feed must not reach the capture step: " + s.verdict);
        }
    }
}
