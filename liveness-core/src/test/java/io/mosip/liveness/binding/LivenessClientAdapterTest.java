package io.mosip.liveness.binding;

import io.mosip.liveness.integration.LivenessClientAdapter;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.session.AttemptLedger;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionClock;
import io.mosip.liveness.session.SessionOutcome;
import io.mosip.liveness.session.SessionOutcome.State;
import io.mosip.liveness.session.SessionPolicy;
import io.mosip.liveness.streamauth.StreamDigestVerifier;
import io.mosip.liveness.vision.Phase0Models;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
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
 * {@link LivenessClientAdapter} with the client's thread layout and REAL components: fixture frames ([SIM] synthetic
 * animated T1) fed at 15 fps from a separate stream thread, the real YuNet/MiniFASNet/SFace pipeline on the worker
 * thread, real asynchronous embeddings, real RS256 capture + B1 statement (TEST-ONLY keys), real CaptureBinder. The
 * ONLY stub: capture PAD pinned at 0.95 so the run is deterministic (the placeholder model is UNCERTAIN ~half the
 * time; PAD behaviour is not under test). [CODE]; not real-device evidence.
 */
class LivenessClientAdapterTest {
    static Phase0Models models;
    static List<byte[]> frames = new ArrayList<>();

    @BeforeAll
    static void load() throws Exception {
        CaptureBinderTest.keys();
        Path root = Paths.get(System.getProperty("phase0.root", "..")).toAbsolutePath().normalize();
        models = Phase0Models.load(root, 1, 320, false);
        try (Stream<Path> s = Files.list(root.resolve("research/fixtures/temporal/animate/T1"))) {
            for (Path p : s.filter(x -> x.toString().endsWith(".jpg")).sorted().collect(Collectors.toList())) {
                frames.add(Files.readAllBytes(p));
            }
        }
    }

    @AfterAll
    static void close() throws Exception {
        models.close();                                         // after every adapter is closed (R10)
    }

    /** Real face analysis of the capture image, PAD pinned (see class doc). */
    static CaptureAnalyzer pinnedPad() {
        VisionCaptureAnalyzer real = new VisionCaptureAnalyzer(models);
        return img -> {
            CaptureAnalyzer.Analysis a = real.analyze(img);
            return new CaptureAnalyzer.Analysis(a.faceCount, 0.95f, a.embedding);
        };
    }

    static final class Run {
        final List<byte[]> deviceEmitted = new ArrayList<>();
        LivenessClientAdapter adapter;
        LivenessSession session;
    }

    /** Streams fixture frames at 15 fps; wire(i, bytes) may substitute what the client receives. */
    static Run start(java.util.function.BiFunction<Integer, byte[], byte[]> wire, int loops) throws Exception {
        SessionPolicy p = new SessionPolicy();
        p.requireStreamAuthentication = true;
        CaptureBinder binder = new CaptureBinder(CaptureBinderTest.verifier, CaptureBinderTest.verifier, pinnedPad(), new CaptureBinder.Policy());
        Run r = new Run();
        r.session = new LivenessSession(p, SessionClock.SYSTEM, binder, new AttemptLedger.InMemory(), "adapter-test",
                new LivenessSession.DeviceIdentity(CaptureBinderTest.SERIAL, "Phase0", "MOCK-FACE-1", "L0"),
                new StreamDigestVerifier(CaptureBinderTest.verifier));
        r.session.start();
        FramePipeline.Config cfg = new FramePipeline.Config();
        cfg.embedEvery = 3;
        cfg.asyncEmbedding = true;
        r.adapter = new LivenessClientAdapter(r.session, models, cfg);
        Thread streamer = new Thread(() -> {
            int n = 0;
            for (int l = 0; l < loops; l++) {
                for (int i = 0; i < frames.size(); i++, n++) {
                    // distinct bytes per emission (a real sensor never repeats a frame byte-for-byte)
                    byte[] emitted = withTrailer(frames.get(i), n);
                    synchronized (r.deviceEmitted) {
                        r.deviceEmitted.add(emitted);
                    }
                    r.adapter.onStreamFrame(wire.apply(n, emitted));
                    try {
                        Thread.sleep(66);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        }, "test-streamer");
        streamer.setDaemon(true);
        streamer.start();
        long t0 = System.currentTimeMillis();
        while (r.session.state() != State.READY_FOR_CAPTURE && System.currentTimeMillis() - t0 < 15_000
                && !r.session.state().terminal()) {
            r.adapter.tick();
            Thread.sleep(20);
        }
        return r;
    }

    /** JPEG COM-free trailer after EOI: decoders ignore it; bytes (and hashes) differ per emission. */
    static byte[] withTrailer(byte[] jpeg, int n) {
        byte[] t = ("#" + n).getBytes(StandardCharsets.US_ASCII);
        byte[] out = java.util.Arrays.copyOf(jpeg, jpeg.length + t.length);
        System.arraycopy(t, 0, out, jpeg.length, t.length);
        return out;
    }

    /** RCAPTURE: capture image = a fixture frame; B1 statement lists everything the device emitted so far. */
    static SessionOutcome capture(Run r) throws Exception {
        LivenessSession.CaptureRequest req = r.adapter.beginCapture();
        // device capture time; the stream keeps flowing. 1.5 s (was 0.7 s): under full-suite CPU load the worker skips
        // frames and a short window could hold fewer than the binder's minStreamEmbeddings (3); thresholds unchanged.
        Thread.sleep(1500);
        byte[] capJpeg = frames.get(15);
        byte[] resp = CaptureBinderTest.response(c -> {
            c.txn = req.transactionId;
            c.ts = Instant.now().minusMillis(100);
            c.bioValue = CaptureBinderTest.iso(capJpeg, 640, 480, 0);
        });
        B1Fixture fx = new B1Fixture(req.transactionId);
        synchronized (r.deviceEmitted) {
            long now = System.currentTimeMillis();
            for (int i = 0; i < r.deviceEmitted.size(); i++) {
                fx.emit(r.deviceEmitted.get(i), now - (r.deviceEmitted.size() - 1 - i) * 66L);
            }
        }
        fx.issuedAt = Instant.now();
        return r.adapter.onCaptureResponse(req.transactionId, fx.attach(resp));
    }

    @Test
    void realPipelineThroughTheAdapterVerifiesWithAuthenticatedStream() throws Exception {
        Run r = start((i, b) -> b, 4);
        assertEquals(State.READY_FOR_CAPTURE, r.session.state(), r.session.outcome().toString());
        SessionOutcome o = capture(r);
        r.adapter.close();
        assertEquals(State.VERIFIED, o.state, o.toString());
        assertTrue(o.streamAuthenticated);
        assertTrue(r.adapter.processedFrames() > 10, "worker processed " + r.adapter.processedFrames());
        assertEquals(0, r.adapter.pipelineErrors());
    }

    @Test
    void substitutedFramesThroughTheAdapterFailAuthentication() throws Exception {
        int[] readyAt = {Integer.MAX_VALUE};
        Run r = start((i, b) -> i > readyAt[0] ? withTrailer(b, 100_000 + i) : b, 4);   // inject after READY
        assertEquals(State.READY_FOR_CAPTURE, r.session.state(), r.session.outcome().toString());
        synchronized (r.deviceEmitted) {
            readyAt[0] = r.deviceEmitted.size();
        }
        SessionOutcome o = capture(r);
        r.adapter.close();
        assertEquals(State.RETRY_PENDING, o.state, o.toString());
        assertEquals(SessionOutcome.Reason.STREAM_AUTH_INTEGRITY_FAILURE, o.reason, o.toString());
        assertEquals(0, o.attackEvents);
    }

    @Test
    void corruptPartsAreNeverEvidenceAndCloseDuringStreamingIsClean() throws Exception {
        Run r = start((i, b) -> i % 5 == 4 ? "not a jpeg".getBytes(StandardCharsets.US_ASCII) : b, 1);
        r.adapter.close();                                      // while the streamer may still be feeding
        r.adapter.close();                                      // idempotent
        r.adapter.onStreamFrame(frames.get(0));                 // ignored after close
        SessionOutcome o = r.session.outcome();
        assertTrue(o.state.terminal(), o.toString());
        assertFalse(o.state == State.VERIFIED);
        assertEquals(0, o.invalidEvidence, "undecodable parts are ineligible frames, not invalid model outputs");
    }
}
