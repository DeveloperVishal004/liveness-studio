package io.mosip.liveness.pipeline;

import io.mosip.liveness.frame.EncodedFrame;
import io.mosip.liveness.frame.LatestFrameMailbox;
import io.mosip.liveness.sbi.JpegInfo;
import io.mosip.liveness.sbi.MjpegParser;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runs the production threading model against a live SBI stream for a fixed duration and measures it:
 * <pre>
 *   reader thread : MjpegParser -> EncodedFrame(seq, receivedNanos) -> LatestFrameMailbox (capacity 1, overwrite)
 *   worker thread : take newest -> FramePipeline.process -> evidence + per-stage timings
 * </pre>
 * Acquisition-side facts (inter-arrival times, JPEG size/quality, corrupt/frozen frames, stalls) are measured on the
 * reader thread so they reflect the device, not the worker.
 */
public final class LiveStreamRun {
    private final InputStream stream;
    private final FramePipeline pipeline;
    private final long durationNanos;
    private final long stallThresholdNanos;

    private final LatestFrameMailbox<EncodedFrame> mailbox = new LatestFrameMailbox<>();
    private final AtomicBoolean stop = new AtomicBoolean();

    // reader-side
    public final LatencyStats interArrival = new LatencyStats();
    private final List<Integer> frameBytes = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Integer> qualityHistogram = Collections.synchronizedMap(new TreeMap<>());
    private final Map<String, Integer> resolutions = Collections.synchronizedMap(new TreeMap<>());
    private final Map<String, Integer> chromaHistogram = Collections.synchronizedMap(new TreeMap<>());
    private final AtomicLong frames = new AtomicLong();
    private final AtomicLong corrupt = new AtomicLong();
    private final AtomicLong identicalToPrevious = new AtomicLong();
    private final AtomicLong stalls = new AtomicLong();
    private volatile String endReason = "duration elapsed";
    private volatile long firstFrameNanos;
    private volatile long lastFrameNanos;

    // worker-side
    public final Map<String, LatencyStats> spans = Collections.synchronizedMap(new LinkedHashMap<>());
    /** Worker take -> evidence ready: the architecture's t_passive_frame. */
    public final LatencyStats passiveFrame = new LatencyStats();
    /** Frame received -> evidence ready (includes mailbox wait). */
    public final LatencyStats frameAge = new LatencyStats();
    public final List<FramePipeline.FrameEvidence> evidence = Collections.synchronizedList(new ArrayList<>());
    private final AtomicLong workerErrors = new AtomicLong();
    private volatile String firstWorkerError;

    private final int warmupFrames;
    private long processedCount;

    public LiveStreamRun(InputStream stream, FramePipeline pipeline, long durationMillis, int warmupFrames) {
        this.stream = stream;
        this.pipeline = pipeline;
        this.warmupFrames = warmupFrames;
        this.durationNanos = TimeUnit.MILLISECONDS.toNanos(durationMillis);
        this.stallThresholdNanos = TimeUnit.MILLISECONDS.toNanos(500);
    }

    public void run() throws InterruptedException {
        long start = System.nanoTime();
        Thread reader = new Thread(this::readLoop, "phase0-stream-reader");
        Thread worker = new Thread(this::workLoop, "phase0-inference-worker");
        reader.setDaemon(true);
        worker.setDaemon(true);
        reader.start();
        worker.start();
        while (System.nanoTime() - start < durationNanos && reader.isAlive()) {
            Thread.sleep(20);
        }
        stop.set(true);
        try {
            stream.close();
        } catch (IOException ignored) {
            // closing a socket stream mid-read is expected here
        }
        mailbox.close();
        reader.join(2000);
        // No timeout: the worker exits after its current frame once the mailbox is closed, and callers close the
        // ONNX sessions next. Closing a session under a running inference is a native use-after-free (R10).
        worker.join();
    }

    private void readLoop() {
        MjpegParser parser = new MjpegParser(stream);
        long seq = 0;
        long prev = 0;
        int prevHash = 0;
        byte[] prevBytes = null;
        try {
            while (!stop.get()) {
                MjpegParser.Part part = parser.next();
                long now = System.nanoTime();
                if (!part.isValid()) {
                    corrupt.incrementAndGet();
                    continue;
                }
                byte[] jpeg = part.jpeg;
                if (frames.get() == 0) {
                    firstFrameNanos = now;
                } else {
                    long gap = now - prev;
                    interArrival.record(gap);
                    if (gap > stallThresholdNanos) {
                        stalls.incrementAndGet();
                    }
                }
                prev = now;
                lastFrameNanos = now;
                frames.incrementAndGet();
                frameBytes.add(jpeg.length);
                int h = Arrays.hashCode(jpeg);
                if (prevBytes != null && h == prevHash && Arrays.equals(jpeg, prevBytes)) {
                    identicalToPrevious.incrementAndGet();
                }
                prevHash = h;
                prevBytes = jpeg;
                if (seq % 15 == 0) {
                    JpegInfo info = JpegInfo.parse(jpeg);
                    qualityHistogram.merge(Integer.toString(info.estimatedQuality), 1, Integer::sum);
                    chromaHistogram.merge(info.chroma, 1, Integer::sum);
                    resolutions.merge(info.width + "x" + info.height + (info.progressive ? "p" : "")
                            + (info.exifOrientation > 1 ? " EXIF-orientation=" + info.exifOrientation : ""), 1, Integer::sum);
                }
                mailbox.offer(new EncodedFrame(seq++, now, System.currentTimeMillis(), "image/jpeg", jpeg));
            }
        } catch (EOFException e) {
            endReason = "device closed stream";
        } catch (IOException e) {
            if (!stop.get()) {
                endReason = "I/O error: " + e.getMessage();
            }
        }
    }

    private void workLoop() {
        try {
            while (!stop.get()) {
                EncodedFrame f = mailbox.take(200, TimeUnit.MILLISECONDS);
                if (f == null) {
                    continue;
                }
                long t0 = System.nanoTime();
                FramePipeline.FrameEvidence ev;
                try {
                    ev = pipeline.process(f);
                } catch (Exception e) {
                    workerErrors.incrementAndGet();
                    if (firstWorkerError == null) {
                        firstWorkerError = e.toString();
                    }
                    continue;
                }
                long t1 = System.nanoTime();
                evidence.add(ev);
                if (++processedCount <= warmupFrames) {
                    continue;
                }
                passiveFrame.record(t1 - t0);
                frameAge.record(t1 - f.receivedNanos());
                for (Map.Entry<String, Long> s : ev.spans.entrySet()) {
                    spans.computeIfAbsent(s.getKey(), k -> new LatencyStats()).record(s.getValue());
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public Map<String, Object> report() {
        Map<String, Object> m = new LinkedHashMap<>();
        long n = frames.get();
        double span = (lastFrameNanos - firstFrameNanos) / 1e9;
        Map<String, Object> acq = new LinkedHashMap<>();
        acq.put("frames", n);
        acq.put("measured_fps", n > 1 && span > 0 ? LatencyStats.round((n - 1) / span) : 0);
        acq.put("inter_arrival", interArrival.summary());
        acq.put("stalls_over_500ms", stalls.get());
        acq.put("corrupt_parts", corrupt.get());
        acq.put("identical_consecutive_frames", identicalToPrevious.get());
        acq.put("resolutions_sampled", new TreeMap<>(resolutions));
        acq.put("jpeg_quality_estimate_sampled", new TreeMap<>(qualityHistogram));
        acq.put("jpeg_chroma_sampled", new TreeMap<>(chromaHistogram));
        List<Integer> sizes;
        synchronized (frameBytes) {
            sizes = new ArrayList<>(frameBytes);
        }
        Collections.sort(sizes);
        acq.put("frame_bytes_p50", sizes.isEmpty() ? 0 : sizes.get(sizes.size() / 2));
        acq.put("end_reason", endReason);
        m.put("acquisition", acq);

        Map<String, Object> proc = new LinkedHashMap<>();
        proc.put("frames_processed", passiveFrame.count());
        proc.put("frames_overwritten_in_mailbox", mailbox.overwrittenCount());
        proc.put("worker_errors", workerErrors.get());
        if (firstWorkerError != null) {
            proc.put("first_worker_error", firstWorkerError);
        }
        proc.put("t_passive_frame", passiveFrame.summary());
        proc.put("frame_age_at_evidence", frameAge.summary());
        Map<String, Object> st = new LinkedHashMap<>();
        synchronized (spans) {
            for (Map.Entry<String, LatencyStats> e : spans.entrySet()) {
                st.put(e.getKey(), e.getValue().summary());
            }
        }
        proc.put("stages", st);
        m.put("processing", proc);
        m.put("evidence", EvidenceSummary.of(evidence));
        return m;
    }
}
