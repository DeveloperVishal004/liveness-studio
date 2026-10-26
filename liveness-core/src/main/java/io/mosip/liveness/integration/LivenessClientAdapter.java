package io.mosip.liveness.integration;

import io.mosip.liveness.frame.EncodedFrame;
import io.mosip.liveness.frame.LatestFrameMailbox;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.session.FrameTag;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.vision.Phase0Models;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The threading glue a Registration Client needs around one {@link LivenessSession}, so the client patch reduces to:
 * <pre>
 *   adapter = new LivenessClientAdapter(session, models, cfg);   // session already start()ed by the caller
 *   streamer thread:  adapter.onStreamFrame(exactJpegPayload);   // per received part, before display
 *   capture:          req = adapter.beginCapture();  raw = RCAPTURE(req.transactionId);  adapter.onCaptureResponse(req.transactionId, raw)
 *   ui:               adapter.tick();  adapter.close();  models.close();   // models AFTER close()
 * </pre>
 * Threads: the caller's stream thread only hashes and tags (cheap, under the session lock); one worker thread runs the
 * vision pipeline <b>outside</b> the session lock on the newest frame (latest-frame mailbox: older frames are skipped
 * for processing but stay in the received-frame log, which B1 needs); the pipeline's embedding thread reports through
 * the frame tag. {@link #close()} stops and joins the worker without a timeout, then closes the pipeline (joins the
 * embedding thread) and shuts the session down; only then may the caller close the ONNX models (R10: closing a model
 * under a running inference is a native use-after-free).
 *
 * <p>The payload passed to {@link #onStreamFrame} must be exactly the JPEG part payload (Content-Length bytes). The
 * desktop client's {@code Streamer.retrieveNextImage} returns one extra trailing byte (R37); trim it first.
 */
public final class LivenessClientAdapter implements AutoCloseable {

    private static final class Item {
        final FrameTag tag;
        final byte[] jpeg;

        Item(FrameTag tag, byte[] jpeg) {
            this.tag = tag;
            this.jpeg = jpeg;
        }
    }

    /** Read-only view of each processed frame (UI/diagnostics). Never influences the decision. */
    public interface FrameObserver {
        void onFrame(FrameTag tag, FramePipeline.FrameEvidence evidence, long processingNanos);
    }

    private volatile FrameObserver observer;
    private final LivenessSession session;
    private final FramePipeline pipeline;
    private final LatestFrameMailbox<Item> mailbox = new LatestFrameMailbox<>();
    private final Thread worker;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicLong received = new AtomicLong();
    private final AtomicLong processed = new AtomicLong();
    private final AtomicLong pipelineErrors = new AtomicLong();

    public LivenessClientAdapter(LivenessSession session, Phase0Models models, FramePipeline.Config cfg) {
        this.session = Objects.requireNonNull(session);
        this.pipeline = new FramePipeline(Objects.requireNonNull(models), Objects.requireNonNull(cfg));
        this.pipeline.setEmbeddingListener(session::onEmbedding);
        this.worker = new Thread(this::work, "liveness-worker");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    /** Called on the stream-receipt thread for every received part (exact JPEG payload). Never blocks on inference. */
    public void onStreamFrame(byte[] jpegPayload) {
        if (closed.get() || jpegPayload == null) {
            return;
        }
        received.incrementAndGet();
        FrameTag tag = session.tagArrival(jpegPayload);     // receipt time + hash, taken here (trusted boundary)
        mailbox.offer(new Item(tag, jpegPayload));
    }

    private void work() {
        while (!closed.get()) {
            Item it;
            try {
                it = mailbox.take(50, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (it == null) {
                continue;
            }
            try {
                long t0 = System.nanoTime();
                FramePipeline.FrameEvidence ev = pipeline.process(
                        new EncodedFrame(it.tag.seq, it.tag.monoNanos, it.tag.wallMillis, "image/jpeg", it.jpeg), it.tag);
                session.onFrameEvidence(it.tag, ev);
                processed.incrementAndGet();
                FrameObserver o = observer;
                if (o != null) {
                    try {
                        o.onFrame(it.tag, ev, System.nanoTime() - t0);
                    } catch (RuntimeException ignored) {
                        // an observer (UI) failure never affects the engine
                    }
                }
            } catch (Exception e) {
                pipelineErrors.incrementAndGet();
                session.onEngineError(e);                   // fail closed: a broken pipeline never yields evidence
            }
        }
    }

    public void setObserver(FrameObserver o) {
        this.observer = o;
    }

    public SessionOutcome tick() {
        return session.tick();
    }

    public LivenessSession.CaptureRequest beginCapture() {
        return session.beginCapture();
    }

    public SessionOutcome onCaptureResponse(String transactionId, byte[] rawResponse) {
        return session.onCaptureResponse(transactionId, rawResponse);
    }

    public long receivedFrames() { return received.get(); }

    public long processedFrames() { return processed.get(); }

    public long pipelineErrors() { return pipelineErrors.get(); }

    /** Ordered shutdown (see class doc). Idempotent. The caller closes the models afterwards. */
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        mailbox.close();
        boolean interrupted = false;
        while (worker.isAlive()) {
            try {
                worker.join();                              // no timeout: never close models under a running inference
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        pipeline.setEmbeddingListener(null);
        pipeline.close();                                   // joins the embedding thread
        session.shutdown();
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
