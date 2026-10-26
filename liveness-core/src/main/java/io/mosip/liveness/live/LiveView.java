package io.mosip.liveness.live;

import javax.imageio.ImageIO;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

/** Draws one UI frame (camera image, face box, status lines). Pure function of its inputs; headless-safe. */
public final class LiveView {
    private LiveView() {}

    public static final String DISCLAIMER = "camera: REAL  |  device: SBI EMULATOR with TEST keys (not certified)  |  "
            + "PAD: MiniFASNet public model, NOT evaluated for this setup  |  1/2/3/SPACE = new trial, Q = quit";

    static final int TEXT_LINES = 6;
    static final int LINE_H = 22;

    public static BufferedImage render(byte[] jpeg, LiveTrialController.Status s, int width, int height) {
        width = Math.max(1, width);                 // a minimised window reports 0x0; painting must not throw
        height = Math.max(1, height);
        BufferedImage out = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = out.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(Color.BLACK);
            g.fillRect(0, 0, width, height);
            List<String> lines = lines(s);
            // headline + text lines + disclaimer, sized from what is actually shown so nothing overprints
            int videoH = Math.max(1, height - (Math.max(TEXT_LINES, lines.size() + 1) * LINE_H) - 20);
            BufferedImage frame = decode(jpeg);
            double scale = 1;
            int ox = 0, oy = 0;
            if (frame != null) {
                scale = Math.min(width / (double) frame.getWidth(), videoH / (double) frame.getHeight());
                int w = (int) (frame.getWidth() * scale), h = (int) (frame.getHeight() * scale);
                ox = (width - w) / 2;
                oy = (videoH - h) / 2;
                g.drawImage(frame, ox, oy, w, h, null);
            } else {
                g.setColor(Color.GRAY);
                g.drawString("waiting for camera frames...", 20, videoH / 2);
            }
            if (s.trialActive && validBox(s.faceBox) && frame != null && s.frameWidth > 0) {
                double fs = scale * frame.getWidth() / s.frameWidth;      // evidence coords -> screen
                g.setStroke(new BasicStroke(3f));
                g.setColor(s.eligible ? new Color(40, 200, 90) : new Color(240, 160, 20));
                g.drawRect(ox + (int) (s.faceBox[0] * fs), oy + (int) (s.faceBox[1] * fs),
                        (int) (s.faceBox[2] * fs), (int) (s.faceBox[3] * fs));
            }
            int y = videoH + 8;
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 18));
            g.setColor(colour(s));
            g.drawString(headline(s), 12, y + 16);
            g.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
            g.setColor(Color.WHITE);
            for (int i = 0; i < lines.size(); i++) {
                g.drawString(lines.get(i), 12, y + 16 + LINE_H * (i + 1));
            }
            g.setColor(new Color(170, 170, 170));
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
            g.drawString(DISCLAIMER, 12, height - 8);
        } finally {
            g.dispose();
        }
        return out;
    }

    private static boolean validBox(float[] b) {
        if (b == null || b.length < 4) {
            return false;
        }
        for (int i = 0; i < 4; i++) {
            if (!Float.isFinite(b[i]) || Math.abs(b[i]) > 1e7f) {
                return false;                       // never draw a box we cannot place sensibly
            }
        }
        return true;
    }

    static String headline(LiveTrialController.Status s) {
        if (s.trial == 0) {
            return "Press 1 (live person), 2 (video on a screen), 3 (still photo) or SPACE (unlabelled) to start a trial";
        }
        return "Trial " + s.trial + (s.label == null ? "" : " [" + s.label + "]") + ":  " + s.verdict;
    }

    /** Text lines under the headline (also used by the headless report). */
    static List<String> lines(LiveTrialController.Status s) {
        List<String> l = new ArrayList<>();
        if (s.trial == 0) {
            return l;
        }
        l.add(String.format("engine state: %-18s reason: %-28s binding: %s", s.state, s.reason,
                s.bindingReason == null ? "-" : s.bindingReason));
        l.add(String.format("face detection: %s   stream PAD P(real): last %s  median %s   (accept >= 0.80, attack < 0.20)",
                s.faceCount < 0 ? "-" : (s.faceCount + " face(s)" + (s.eligible ? ", eligible" : (s.ineligibleReason == null
                        ? "" : ", not eligible: " + s.ineligibleReason))), fmt(s.lastPad), fmt(s.medianPad)));
        l.add(String.format("signed capture: %s   capture PAD P(real): %s   bind: %s",
                s.captureIssued ? "requested" : "not yet", fmt(s.capturePad), s.bindMs == null ? "-" : String.format("%.0f ms", s.bindMs)));
        l.add(String.format("latency: frame processing %.1f ms, frame age at evidence %.1f ms   counters: subject attacks %d, channel %d",
                s.frameProcessingMs, s.frameAgeMs, s.attackEvents, s.channelEvents));
        if (s.detail != null && !s.detail.isEmpty()) {
            l.add("detail: " + s.detail);
        }
        String hint = hint(s);
        if (hint != null) {
            l.addAll(wrap("hint: " + hint, 110));
        }
        return l;
    }

    /** Greedy word wrap; continuation lines are indented under the first. */
    static List<String> wrap(String text, int max) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (String w : text.split(" ")) {
            if (cur.length() > 0 && cur.length() + 1 + w.length() > max) {
                out.add(cur.toString());
                cur = new StringBuilder("      ");
            }
            if (cur.length() > 0 && cur.charAt(cur.length() - 1) != ' ') {
                cur.append(' ');
            }
            cur.append(w);
        }
        out.add(cur.toString());
        return out;
    }

    /**
     * Operator guidance only; it never changes a decision. Measured on a real 960x540 webcam, a normal blink moves the
     * motion statistic no more than holding still, while smiling or talking exceeds the engine's trigger level.
     */
    static String hint(LiveTrialController.Status s) {
        if ("STATIC_REPLAY_SUSPECT".equals(s.reason)) {
            return "no facial movement seen: blinking alone is too small on this camera. Smile or speak naturally while looking "
                    + "at the camera, then press 1 to retry.";
        }
        if ("CAPTURING".equals(s.state)) {
            return "look at the camera, face frontal, and smile or speak naturally (blinking alone is not enough).";
        }
        return null;
    }

    static Color colour(LiveTrialController.Status s) {
        if ("VERIFIED".equals(s.state)) {
            return new Color(60, 220, 100);
        }
        if ("REJECTED_ATTACK".equals(s.state) || s.state.startsWith("FAILED") || s.state.startsWith("ERROR")) {
            return new Color(255, 80, 80);
        }
        return new Color(255, 200, 60);
    }

    static String fmt(Float f) {
        return f == null ? "-" : String.format("%.2f", f);
    }

    private static BufferedImage decode(byte[] jpeg) {
        if (jpeg == null) {
            return null;
        }
        try {
            return ImageIO.read(new ByteArrayInputStream(jpeg));
        } catch (Exception e) {
            return null;                                        // a corrupt part is simply not displayed
        }
    }
}
