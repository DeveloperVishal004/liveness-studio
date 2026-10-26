package io.mosip.liveness.live;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Rendering and wording of the webcam view (headless). [CODE] */
class LiveViewTest {
    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    static LiveTrialController.Status status(String state, String reason, String verdict) {
        LiveTrialController.Status s = new LiveTrialController.Status();
        s.trial = 3;
        s.trialActive = true;
        s.state = state;
        s.reason = reason;
        s.verdict = verdict;
        s.faceCount = 1;
        s.eligible = true;
        s.lastPad = 0.91f;
        s.medianPad = 0.88f;
        s.faceBox = new float[] {100, 80, 200, 240};
        s.frameWidth = 640;
        s.frameHeight = 480;
        return s;
    }

    @Test
    void rendersWithAndWithoutAFrame() throws Exception {
        byte[] jpeg = Files.readAllBytes(Paths.get(System.getProperty("phase0.root", "..")).resolve("research/fixtures/temporal/animate/T1/f000.jpg"));
        BufferedImage a = LiveView.render(jpeg, status("CAPTURING", "NONE", "collecting stream evidence..."), 1100, 820);
        assertEquals(1100, a.getWidth());
        BufferedImage b = LiveView.render(null, new LiveTrialController.Status(), 800, 600);
        assertEquals(600, b.getHeight());
        LiveView.render("not a jpeg".getBytes(), status("CAPTURING", "NONE", "x"), 640, 480);   // corrupt part: no exception
    }

    @Test
    void motionHintIsGuidanceOnlyAndNeverAVerdict() {
        LiveTrialController.Status s = status("RETRY_PENDING", "STATIC_REPLAY_SUSPECT", "NOT ACCEPTED - retry: STATIC_REPLAY_SUSPECT");
        String text = String.join("\n", LiveView.lines(s));
        assertTrue(text.contains("hint: no facial movement seen") && text.toLowerCase().contains("smile or speak"), text);
        assertFalse(text.toUpperCase().contains("VERIFIED"), text);
        assertEquals("NOT ACCEPTED - retry: STATIC_REPLAY_SUSPECT", s.verdict);          // the hint does not touch the decision
        assertTrue(String.join("\n", LiveView.lines(status("CAPTURING", "NONE", "collecting stream evidence..."))).contains("hint:"));
        assertFalse(String.join("\n", LiveView.lines(status("VERIFIED", "OK", "VERIFIED by the engine"))).contains("hint:"));
    }

    @Test
    void longHintWrapsAndEveryLineFitsTheWindowText() {
        LiveTrialController.Status s = status("RETRY_PENDING", "STATIC_REPLAY_SUSPECT", "NOT ACCEPTED - retry: STATIC_REPLAY_SUSPECT");
        for (String line : LiveView.lines(s)) {
            assertTrue(line.length() <= 135, line.length() + ": " + line);
        }
        assertTrue(LiveView.wrap("a b c", 110).size() == 1);
        LiveView.render(null, s, 1100, 820);        // renders with the extra lines without exception
    }

    @Test
    void wordingShowsPadAndNeverClaimsLivenessFromDetection() {
        LiveTrialController.Status s = status("CAPTURING", "NONE", "collecting stream evidence...");
        String text = String.join("\n", LiveView.lines(s)) + LiveView.headline(s);
        assertTrue(text.contains("last 0.91") && text.contains("median 0.88"), text);
        assertTrue(text.contains("1 face(s), eligible"), text);
        assertFalse(text.toUpperCase().contains("VERIFIED"), "a detected face is not a decision: " + text);
        assertFalse(text.toUpperCase().contains("LIVE "), text);
        assertTrue(LiveView.DISCLAIMER.contains("TEST keys") && LiveView.DISCLAIMER.contains("NOT evaluated"));
    }
}
