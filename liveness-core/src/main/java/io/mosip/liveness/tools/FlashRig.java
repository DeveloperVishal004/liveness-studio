package io.mosip.liveness.tools;

import io.mosip.liveness.pipeline.LatencyStats;
import io.mosip.liveness.sbi.MjpegParser;
import io.mosip.liveness.sbi.SbiClient;
import io.mosip.liveness.vision.BgrImage;
import io.mosip.liveness.vision.ImageDecoder;

import java.awt.Color;
import java.awt.Frame;
import java.awt.GraphicsEnvironment;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Sensor-to-host latency rig. Point the face device at this screen; the rig toggles a full-screen window between
 * black and white at random instants and measures when the change shows up in received stream frames.
 *
 * <p>Procedure: (1) 2 s black, record the settled brightness {@code lo}; (2) 2 s white, record {@code hi};
 * (3) {@code cycles} measured toggles at random 1.5-2.5 s intervals, each detected when a received frame crosses
 * {@code (lo+hi)/2}. The figure includes display latency (typically 1-3 refresh periods), so it is an
 * <em>upper bound</em> on device pipeline latency. It sets the challenge freshness guard ({@code guardMs}).
 */
final class FlashRig {
    private FlashRig() {}

    static Map<String, Object> measure(SbiClient sbi, String serial, int cycles) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        if (GraphicsEnvironment.isHeadless()) {
            r.put("error", "headless environment: flash rig needs a display");
            return r;
        }
        Frame win = new Frame("phase0-flash");
        win.setUndecorated(true);
        win.setBackground(Color.BLACK);
        win.setExtendedState(Frame.MAXIMIZED_BOTH);
        win.setVisible(true);
        SecureRandom rng = new SecureRandom();
        LatencyStats lat = new LatencyStats();
        try (InputStream s = sbi.openStream(serial, "0", (cycles * 3L + 10) * 1000L)) {
            MjpegParser parser = new MjpegParser(s);
            ImageDecoder dec = new ImageDecoder();
            double lo = settle(parser, dec, win, Color.BLACK, 2000);
            double hi = settle(parser, dec, win, Color.WHITE, 2000);
            r.put("calibration_lo_hi", new double[] {Math.round(lo), Math.round(hi)});
            if (hi - lo < 20) {
                r.put("error", "insufficient contrast between black and white screen (" + lo + " vs " + hi + "); aim the device at the screen");
                return r;
            }
            double mid = (lo + hi) / 2;
            boolean white = true;
            for (int c = 0; c < cycles; c++) {
                long wait = 1_500_000_000L + (long) (rng.nextDouble() * 1_000_000_000L);
                long until = System.nanoTime() + wait;
                while (System.nanoTime() < until) {
                    parser.next();                      // keep draining so frames stay current
                }
                white = !white;
                win.setBackground(white ? Color.WHITE : Color.BLACK);
                win.repaint();
                long toggled = System.nanoTime();
                long deadline = toggled + 3_000_000_000L;
                while (System.nanoTime() < deadline) {
                    MjpegParser.Part p = parser.next();
                    if (!p.isValid()) {
                        continue;
                    }
                    double b = meanGrey(dec.decode(p.jpeg));
                    if (white ? b > mid : b < mid) {
                        lat.record(System.nanoTime() - toggled);
                        break;
                    }
                }
            }
        } finally {
            win.dispose();
        }
        r.put("cycles_detected", lat.count());
        r.put("cycles_requested", cycles);
        r.put("toggle_to_frame_received", lat.summary());
        r.put("note", "includes display latency; upper bound on sensor->host latency");
        return r;
    }

    private static double settle(MjpegParser parser, ImageDecoder dec, Frame win, Color colour, long millis) throws Exception {
        win.setBackground(colour);
        win.repaint();
        long end = System.nanoTime() + millis * 1_000_000L;
        List<Double> tail = new ArrayList<>();
        while (System.nanoTime() < end) {
            MjpegParser.Part p = parser.next();
            if (p.isValid()) {
                tail.add(meanGrey(dec.decode(p.jpeg)));
            }
        }
        if (tail.isEmpty()) {
            throw new IllegalStateException("no frames during calibration");
        }
        List<Double> last = new ArrayList<>(tail.subList(tail.size() / 2, tail.size())); // settled half
        Collections.sort(last);
        return last.get(last.size() / 2);
    }

    private static double meanGrey(BgrImage img) {
        long s = 0;
        int n = 0;
        for (int i = 0; i + 2 < img.data.length; i += 3 * 16) {
            s += (img.data[i] & 0xFF) + (img.data[i + 1] & 0xFF) + (img.data[i + 2] & 0xFF);
            n += 3;
        }
        return (double) s / n;
    }
}
