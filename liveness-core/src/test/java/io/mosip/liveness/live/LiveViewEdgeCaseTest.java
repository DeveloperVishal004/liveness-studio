package io.mosip.liveness.live;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The window must keep painting for any window size, frame or status values (a paint exception would freeze the UI). [CODE] */
class LiveViewEdgeCaseTest {
    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    static byte[] jpeg() throws Exception {
        return Files.readAllBytes(Paths.get(System.getProperty("phase0.root", "..")).resolve("research/fixtures/temporal/animate/T1/f000.jpg"));
    }

    @Test
    void anyWindowSizeRendersEvenMinimisedOrTiny() throws Exception {
        byte[] jpeg = jpeg();
        LiveTrialController.Status s = LiveViewTest.status("RETRY_PENDING", "STATIC_REPLAY_SUSPECT", "NOT ACCEPTED - retry: STATIC_REPLAY_SUSPECT");
        for (int[] size : new int[][] {{0, 0}, {1, 1}, {0, 500}, {500, 0}, {10, 10}, {100, 50}, {300, 100}, {2000, 40}, {3000, 2000}}) {
            BufferedImage img = assertDoesNotThrow(() -> LiveView.render(jpeg, s, size[0], size[1]), size[0] + "x" + size[1]);
            assertNotNull(img);
            assertTrue(img.getWidth() >= 1 && img.getHeight() >= 1);
        }
    }

    @Test
    void hostileStatusValuesNeverBreakPainting() throws Exception {
        byte[] jpeg = jpeg();
        LiveTrialController.Status s = LiveViewTest.status("CAPTURING", "NONE", null);
        s.verdict = null;
        s.reason = null;
        s.lastPad = Float.NaN;
        s.medianPad = Float.POSITIVE_INFINITY;
        s.capturePad = -1f;
        s.frameProcessingMs = Double.NaN;
        s.frameAgeMs = Double.NEGATIVE_INFINITY;
        s.bindMs = Double.NaN;
        s.faceBox = new float[] {Float.NaN, Float.POSITIVE_INFINITY, -1e30f, 1e30f};
        s.frameWidth = 0;
        s.frameHeight = -5;
        s.detail = "x".repeat(5000);
        assertDoesNotThrow(() -> LiveView.render(jpeg, s, 1100, 820));
        s.frameWidth = 640;
        s.faceBox = new float[] {-500, -500, 1e9f, 1e9f};             // box far outside the picture
        assertDoesNotThrow(() -> LiveView.render(jpeg, s, 1100, 820));
        s.faceBox = new float[] {1, 2};                               // truncated box
        assertDoesNotThrow(() -> LiveView.render(jpeg, s, 1100, 820));
        s.faceBox = null;
        assertDoesNotThrow(() -> LiveView.render(null, s, 1100, 820));
    }

    @Test
    void wrapHandlesEmptyOverlongAndOddInput() {
        assertEquals(1, LiveView.wrap("", 110).size());
        assertEquals("", LiveView.wrap("", 110).get(0));
        assertEquals(1, LiveView.wrap("short", 110).size());
        String longWord = "x".repeat(400);
        assertEquals(1, LiveView.wrap(longWord, 110).size(), "an unbreakable word stays on one line, never dropped");
        assertTrue(LiveView.wrap(longWord, 110).get(0).contains(longWord));
        java.util.List<String> many = LiveView.wrap(("word ").repeat(300).trim(), 40);
        assertTrue(many.size() > 10);
        for (String l : many) {
            assertTrue(l.length() <= 40 + 6, l.length() + ": " + l);
        }
        assertEquals(1, LiveView.wrap("   ", 10).size());
        assertDoesNotThrow(() -> LiveView.wrap("a b c", 1));
        assertDoesNotThrow(() -> LiveView.wrap("a b c", 0));
    }

    @Test
    void wrappingNeverLosesOrAddsWords() {
        String text = "hint: no facial movement seen: blinking alone is too small on this camera. Smile or speak naturally";
        for (int max : new int[] {1, 5, 20, 60, 110, 500}) {
            String joined = String.join(" ", LiveView.wrap(text, max)).trim().replaceAll("\\s+", " ");
            assertEquals(text, joined, "max " + max);
        }
    }

    @Test
    void aDetectionAloneNeverProducesAVerifiedHeadlineWhateverTheNumbers() {
        for (String state : new String[] {"IDLE", "CAPTURING", "RETRY_PENDING", "REJECTED_ATTACK", "ERROR_ENGINE", "FAILED_POLICY", "EXPIRED"}) {
            LiveTrialController.Status s = LiveViewTest.status(state, "NONE", LiveTrialController.verdict(outcome(state)));
            s.lastPad = 1.0f;
            s.medianPad = 1.0f;
            s.capturePad = 1.0f;
            String text = LiveView.headline(s) + String.join("\n", LiveView.lines(s));
            assertFalse(text.toUpperCase().contains("VERIFIED"), state + ": " + text);
        }
    }

    private static io.mosip.liveness.session.SessionOutcome outcome(String state) {
        io.mosip.liveness.session.SessionHarness.StubVerifier v = new io.mosip.liveness.session.SessionHarness.StubVerifier();
        io.mosip.liveness.session.SessionHarness h = new io.mosip.liveness.session.SessionHarness(new io.mosip.liveness.session.SessionPolicy(),
                new io.mosip.liveness.session.AttemptLedger.InMemory(), v, null);
        h.session.start();
        return h.session.outcome();
    }
}
