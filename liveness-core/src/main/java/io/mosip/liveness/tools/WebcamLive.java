package io.mosip.liveness.tools;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.liveness.binding.CaptureBinder;
import io.mosip.liveness.binding.VisionCaptureAnalyzer;
import io.mosip.liveness.live.LiveApiServer;
import io.mosip.liveness.live.LiveSnapshot;
import io.mosip.liveness.live.LiveTrialController;
import io.mosip.liveness.live.LiveWindow;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.sbi.JwsVerifier;
import io.mosip.liveness.sbi.MjpegParser;
import io.mosip.liveness.sbi.SbiClient;
import io.mosip.liveness.session.LivenessSession;
import io.mosip.liveness.session.SessionPolicy;
import io.mosip.liveness.vision.Phase0Models;

import java.awt.Desktop;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * {@code webcam-live}: live trials against an SBI device (typically {@code tools/mock-sbi/mock_sbi.py --camera 0}, an
 * SBI emulator around the laptop webcam). Real frames go through the real engine; the window shows the engine's own
 * decision. {@code --headless --trials N} runs N trials without a window and writes a JSON report.
 */
final class WebcamLive {
    private WebcamLive() {}

    static Map<String, Object> run(Phase0Cli.Args a) throws Exception {
        JwsVerifier trust = JwsVerifier.fromPem(Paths.get(a.get("trust")));
        SbiClient sbi = new SbiClient(a.getInt("port", 4501));
        JsonNode info = trust.verify(sbi.info().get(0).path("deviceInfo").asText(), new java.util.Date()).payload;
        JsonNode digitalId = trust.verify(info.path("digitalId").asText(), new java.util.Date()).payload;
        String serial = digitalId.path("serialNo").asText();
        LivenessSession.DeviceIdentity device = new LivenessSession.DeviceIdentity(serial,
                digitalId.path("make").asText(null), digitalId.path("model").asText(null), info.path("certification").asText(null));
        JsonNode specs = info.path("specVersion");
        String specVersion = specs.isArray() && specs.size() > 0 ? specs.get(specs.size() - 1).asText() : "1.0";
        String env = info.path("env").asText("Developer");
        String purpose = info.path("purpose").asText("Registration");

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("evidence_class", "REAL camera frames through an SBI EMULATOR with TEST keys (not a certified device); "
                + "PAD model MiniFASNet (public, not evaluated for this setup). Individual trials, not an accuracy measurement.");
        try (Phase0Models models = Phase0Cli.models(a)) {
            FramePipeline.Config cfg = Phase0Cli.pipelineConfig(a);
            CaptureBinder binder = new CaptureBinder(trust, trust, new VisionCaptureAnalyzer(models),
                    CaptureBinder.Policy.conservativeAcceptGate());
            SessionPolicy sessionPolicy = new SessionPolicy();
            CaptureBinder.Policy binderPolicy = CaptureBinder.Policy.conservativeAcceptGate();
            LiveTrialController controller = new LiveTrialController(models, cfg, sessionPolicy, binder, device,
                    txn -> sbi.rcaptureFaceSbi10(txn, env, purpose, specVersion, serial, 10_000));
            AtomicBoolean stop = new AtomicBoolean();
            InputStream stream = sbi.openStream(serial, "0", 3_600_000);
            Thread reader = new Thread(() -> {
                MjpegParser parser = new MjpegParser(stream);
                try {
                    while (!stop.get()) {
                        MjpegParser.Part part = parser.next();
                        if (part.isValid()) {
                            controller.onStreamFrame(part.jpeg);
                        }
                    }
                } catch (IOException e) {
                    if (!stop.get()) {
                        System.err.println("stream ended: " + e);
                    }
                }
            }, "webcam-stream");
            reader.setDaemon(true);
            reader.start();
            try {
                if (a.has("serve")) {
                    LiveSnapshot.Thresholds th = new LiveSnapshot.Thresholds();
                    th.streamAccept = sessionPolicy.streamAccept;
                    th.streamAttack = sessionPolicy.streamAttack;
                    th.captureAccept = binderPolicy.padCaptureMin;
                    th.captureAttack = binderPolicy.padAttack;
                    th.subjectMinCosine = binderPolicy.subjectMinCosine;
                    th.motionTrigger = sessionPolicy.staticPhotoThreshold;
                    th.minFaceHeightPx = cfg.minFaceHeightPx;
                    th.minSharpness = cfg.minSharpness;
                    th.minStreamEmbeddings = binderPolicy.minStreamEmbeddings;
                    th.attackMinFrames = sessionPolicy.attackMinFrames;
                    Path ui = Paths.get(a.get("ui-dir", a.get("root", "..") + "/frontend/dist"));
                    if (!Files.isDirectory(ui)) {
                        System.err.println("note: frontend not built (" + ui + "); serving the API only. Build it: cd frontend && npm install && npm run build");
                        ui = null;
                    }
                    CountDownLatch quit = new CountDownLatch(1);
                    try (LiveApiServer srv = new LiveApiServer(controller, th, a.get("camera-label", "webcam"), ui,
                            a.getInt("ui-port", 0), null, quit::countDown)) {
                        srv.start();
                        System.err.println("UI_URL=" + srv.url());
                        if (a.has("open-browser") && Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                            try {
                                Desktop.getDesktop().browse(java.net.URI.create(srv.url()));
                            } catch (Exception e) {
                                System.err.println("could not open a browser; open the URL above yourself");
                            }
                        }
                        quit.await();
                    }
                    controller.close();                     // records a trial still running at quit as unfinished
                    List<Map<String, Object>> trials = new ArrayList<>();
                    for (LiveTrialController.Status s : controller.history()) {
                        trials.add(statusMap(s));
                    }
                    report.put("trials", trials);
                } else if (a.has("headless")) {
                    List<Map<String, Object>> trials = new ArrayList<>();
                    int n = a.getInt("trials", 1);
                    for (int i = 0; i < n; i++) {
                        controller.startTrial();
                        long t0 = System.currentTimeMillis();
                        LiveTrialController.Status s = controller.poll();
                        while (s.trialActive && System.currentTimeMillis() - t0 < 30_000) {
                            Thread.sleep(50);
                            s = controller.poll();
                        }
                        trials.add(statusMap(s));
                        System.err.println("trial " + s.trial + ": " + s.verdict + (s.detail == null ? "" : "  [" + s.detail + "]"));
                    }
                    report.put("trials", trials);
                } else {
                    LiveWindow.show(controller);
                    controller.close();                     // records a trial still running at close as unfinished
                    List<Map<String, Object>> trials = new ArrayList<>();
                    for (LiveTrialController.Status s : controller.history()) {
                        trials.add(statusMap(s));
                    }
                    report.put("trials", trials);
                }
            } finally {
                stop.set(true);
                try {
                    stream.close();
                } catch (IOException ignored) {
                    // closing mid-read is expected
                }
                reader.join(3000);
                controller.close();                         // joins the worker before the models close (R10)
            }
            report.put("models", models.versions);
        }
        return report;
    }

    static Map<String, Object> statusMap(LiveTrialController.Status s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("trial", s.trial);
        m.put("label", s.label);
        m.put("unfinished", s.unfinished);
        m.put("state", s.state);
        m.put("reason", s.reason);
        m.put("binding_reason", s.bindingReason);
        m.put("verdict", s.verdict);
        m.put("stream_pad_median", s.medianPad);
        m.put("stream_pad_last", s.lastPad);
        m.put("capture_issued", s.captureIssued);
        m.put("capture_pad", s.capturePad);
        m.put("bind_ms", s.bindMs);
        m.put("frame_processing_ms", s.frameProcessingMs);
        m.put("detail", s.detail);
        return m;
    }
}
