package io.mosip.liveness.pipeline;

import io.mosip.liveness.frame.LatestFrameMailbox;
import io.mosip.liveness.vision.BgrImage;
import io.mosip.liveness.vision.Face;
import io.mosip.liveness.vision.SFaceEmbedder;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Computes subject embeddings for capture binding <em>off</em> the per-frame critical path.
 *
 * <p>Phase-0 sweep: SFace costs ~18 ms per call (M1), and computing it inline every 5th frame raised
 * {@code t_passive_frame} p95 from ~11 ms to ~29 ms. The worker offers (image, face) pairs into a capacity-1 mailbox and a
 * low-priority thread embeds whatever is newest.
 *
 * <p>Every embedding keeps the frame's sequence number, its <b>monotonic arrival time</b> and an opaque attachment (the
 * session's frame tag), and is delivered to the {@link Listener}. The session uses these to place embeddings on the
 * capture timeline and to reject embeddings from a stale epoch or session (temporal binding). Embeddings are kept in
 * memory only and are never logged or persisted.
 */
public final class EmbeddingSampler implements AutoCloseable {

    /** Receives embeddings off the critical path. Called on the sampler thread; implementations must be thread-safe. */
    public interface Listener {
        void onEmbedding(long seq, long receivedNanos, float[] embedding, Object attachment);
    }

    private static final class Job {
        final long seq;
        final long receivedNanos;
        final BgrImage img;
        final Face face;
        final Object attachment;

        Job(long seq, long receivedNanos, BgrImage img, Face face, Object attachment) {
            this.seq = seq;
            this.receivedNanos = receivedNanos;
            this.img = img;
            this.face = face;
            this.attachment = attachment;
        }
    }

    private final SFaceEmbedder embedder;
    private final LatestFrameMailbox<Job> mailbox = new LatestFrameMailbox<>();
    private final Deque<float[]> recent = new ArrayDeque<>();
    private final int capacity;
    private final Thread thread;
    private final AtomicLong computed = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();
    private volatile Listener listener;
    private volatile boolean running = true;

    public EmbeddingSampler(SFaceEmbedder embedder, int capacity) {
        this.embedder = embedder;
        this.capacity = capacity;
        this.thread = new Thread(this::loop, "liveness-embedding-sampler");
        thread.setDaemon(true);
        thread.setPriority(Thread.MIN_PRIORITY);
        thread.start();
    }

    public void setListener(Listener l) {
        this.listener = l;
    }

    /** Non-blocking; an older pending job is replaced. */
    public void offer(long seq, BgrImage img, Face face) {
        offer(seq, System.nanoTime(), img, face, null);
    }

    /** Non-blocking; an older pending job is replaced (the dropped frame simply gets no embedding). */
    public void offer(long seq, long receivedNanos, BgrImage img, Face face, Object attachment) {
        mailbox.offer(new Job(seq, receivedNanos, img, face, attachment));
    }

    /** Up to {@code n} most recent embeddings (newest last). Diagnostic tools only; sessions use the listener. */
    public synchronized List<float[]> recent(int n) {
        List<float[]> all = new ArrayList<>(recent);
        return all.subList(Math.max(0, all.size() - n), all.size());
    }

    public long computedCount() { return computed.get(); }
    public long failureCount() { return failures.get(); }

    private void loop() {
        while (running) {
            try {
                Job j = mailbox.take(200, TimeUnit.MILLISECONDS);
                if (j == null) {
                    continue;
                }
                float[] e = embedder.embed(j.img, j.face);
                synchronized (this) {
                    recent.addLast(e);
                    while (recent.size() > capacity) {
                        recent.removeFirst();
                    }
                }
                computed.incrementAndGet();
                Listener l = listener;
                if (l != null) {
                    l.onEmbedding(j.seq, j.receivedNanos, e, j.attachment);
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                failures.incrementAndGet(); // a failed embedding only reduces binding evidence; it never adds any
            }
        }
    }

    /**
     * Stops and <b>joins</b> the sampler thread. Must complete before the ONNX sessions are closed: closing a session
     * while this thread is inside {@code run()} is a native use-after-free (Phase-0 R10: JVM-exit aborts).
     */
    @Override
    public void close() {
        running = false;
        mailbox.close();
        thread.interrupt();
        try {
            thread.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (thread.isAlive()) {
            throw new IllegalStateException("embedding sampler did not stop; refusing to let sessions be closed under it");
        }
        synchronized (this) {
            recent.clear();
        }
    }
}
