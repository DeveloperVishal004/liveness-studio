package io.mosip.liveness.live;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.concurrent.CountDownLatch;

/** Swing window around {@link LiveView}: repaints ~30 times per second; 1/2/3 start a labelled trial (live/video/photo), SPACE an unlabelled one, Q quits. */
public final class LiveWindow {
    private LiveWindow() {}

    /** Blocks until the window is closed. */
    public static void show(LiveTrialController controller) throws InterruptedException {
        CountDownLatch closed = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            JFrame f = new JFrame("MOSIP face liveness - webcam test (SBI emulator, TEST keys; not a certified device)");
            JPanel panel = new JPanel() {
                LiveTrialController.Status last = new LiveTrialController.Status();

                @Override
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    last = controller.poll();
                    g.drawImage(LiveView.render(controller.latestFrame(), last, getWidth(), getHeight()), 0, 0, null);
                }
            };
            panel.setPreferredSize(new Dimension(1100, 820));
            f.add(panel);
            f.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_SPACE || e.getKeyCode() == KeyEvent.VK_ENTER) {
                        controller.startTrial();
                    } else if (e.getKeyCode() == KeyEvent.VK_1 || e.getKeyCode() == KeyEvent.VK_NUMPAD1) {
                        controller.startTrial("live");          // labels are recorded only; same engine path
                    } else if (e.getKeyCode() == KeyEvent.VK_2 || e.getKeyCode() == KeyEvent.VK_NUMPAD2) {
                        controller.startTrial("video");
                    } else if (e.getKeyCode() == KeyEvent.VK_3 || e.getKeyCode() == KeyEvent.VK_NUMPAD3) {
                        controller.startTrial("photo");
                    } else if (e.getKeyCode() == KeyEvent.VK_Q || e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                        f.dispose();
                    }
                }
            });
            f.addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosed(WindowEvent e) {
                    closed.countDown();
                }
            });
            f.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            f.pack();
            f.setLocationRelativeTo(null);
            f.setVisible(true);
            f.setAlwaysOnTop(true); // bring in front of the terminal/editor that launched it, then release
            f.toFront();
            f.requestFocus();
            f.setAlwaysOnTop(false);
            new Timer(33, e -> panel.repaint()).start();
        });
        closed.await();
    }
}
