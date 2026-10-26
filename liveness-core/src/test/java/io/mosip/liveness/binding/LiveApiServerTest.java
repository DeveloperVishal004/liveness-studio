package io.mosip.liveness.binding;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.liveness.live.LiveApiServer;
import io.mosip.liveness.live.LiveSnapshot;
import io.mosip.liveness.live.LiveTrialController;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract and security tests for the local API, through the real pipeline and a real HTTP client. The API only
 * passes the engine's outcome through; these tests prove it neither rewrites a decision nor accepts foreign callers. [CODE]
 */
class LiveApiServerTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static final HttpClient HTTP = HttpClient.newHttpClient();

    @BeforeAll
    static void load() throws Exception {
        LivenessClientAdapterTest.load();
    }

    @AfterAll
    static void close() throws Exception {
        LivenessClientAdapterTest.close();
    }

    static final class Rig implements AutoCloseable {
        final LiveTrialController controller;
        final LiveApiServer server;
        final AtomicBoolean quit = new AtomicBoolean();
        final String base;

        Rig(Path ui) throws Exception {
            controller = LiveTrialControllerTest.controller(LivenessClientAdapterTest.pinnedPad(), LiveTrialControllerTest.signedCapture());
            server = new LiveApiServer(controller, new LiveSnapshot.Thresholds(), "test camera", ui, 0, null, () -> quit.set(true));
            server.start();
            base = "http://127.0.0.1:" + server.port();
        }

        HttpResponse<String> get(String path) throws Exception {
            return HTTP.send(HttpRequest.newBuilder(URI.create(base + path)).header("X-Token", server.token()).build(),
                    HttpResponse.BodyHandlers.ofString());
        }

        HttpResponse<String> post(String path, String body) throws Exception {
            return HTTP.send(HttpRequest.newBuilder(URI.create(base + path)).header("X-Token", server.token())
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        }

        JsonNode status() throws Exception {
            return JSON.readTree(get("/api/status").body());
        }

        /** Feeds frames at 15 fps until stopped, as the stream reader would. */
        Thread feeder(List<byte[]> frames, AtomicBoolean stop) {
            Thread t = new Thread(() -> {
                int n = 0;
                while (!stop.get()) {
                    controller.onStreamFrame(LivenessClientAdapterTest.withTrailer(frames.get(n % frames.size()), n));
                    n++;
                    try {
                        Thread.sleep(66);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }, "test-feeder");
            t.setDaemon(true);
            t.start();
            return t;
        }

        @Override
        public void close() {
            server.close();
            server.close();                                     // idempotent
            controller.close();
        }
    }

    /** Raw HTTP so the test can send a Host/Origin header the JDK client would refuse to set. */
    static String raw(int port, String request) throws Exception {
        try (Socket s = new Socket("127.0.0.1", port)) {
            s.setSoTimeout(5000);
            OutputStream o = s.getOutputStream();
            o.write(request.getBytes(StandardCharsets.US_ASCII));
            o.flush();
            InputStream in = s.getInputStream();
            byte[] buf = new byte[4096];
            int n = in.read(buf);
            return n <= 0 ? "" : new String(buf, 0, n, StandardCharsets.UTF_8);
        }
    }

    @Test
    void everyApiCallNeedsTheTokenAndALoopbackHost() throws Exception {
        try (Rig r = new Rig(null)) {
            assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/status")).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/status")).header("X-Token", "wrong").build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/status?t=")).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/frame.jpg")).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/trial")).POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(200, r.get("/api/status").statusCode());
            assertEquals(200, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/status?t=" + r.server.token())).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            // DNS-rebinding: a request addressed to another host name is refused even with the right token
            String resp = raw(r.server.port(), "GET /api/status HTTP/1.1\r\nHost: evil.example\r\nX-Token: " + r.server.token() + "\r\nConnection: close\r\n\r\n");
            assertTrue(resp.startsWith("HTTP/1.1 403"), resp);
            String noHost = raw(r.server.port(), "GET /api/status HTTP/1.0\r\nX-Token: " + r.server.token() + "\r\n\r\n");
            assertTrue(noHost.contains(" 403 "), noHost);
            assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/nothing")).build(), HttpResponse.BodyHandlers.ofString()).statusCode(),
                    "even unknown paths do not reveal anything without the token");
        }
    }

    @Test
    void mutatingCallsRefuseForeignOriginsBadBodiesBadLabelsAndWrongMethods() throws Exception {
        try (Rig r = new Rig(null)) {
            String foreign = raw(r.server.port(), "POST /api/trial HTTP/1.1\r\nHost: 127.0.0.1:" + r.server.port() + "\r\nOrigin: http://evil.example\r\n"
                    + "X-Token: " + r.server.token() + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            assertTrue(foreign.startsWith("HTTP/1.1 403"), foreign);
            assertEquals(0, r.controller.history().size());

            assertEquals(413, r.post("/api/trial", "{\"label\":\"" + "a".repeat(5000) + "\"}").statusCode());
            assertEquals(400, r.post("/api/trial", "not json").statusCode());
            for (String bad : new String[] {"Live", "../x", "a b", "1abc", "x".repeat(33), "<script>"}) {
                assertEquals(400, r.post("/api/trial", "{\"label\":\"" + bad + "\"}").statusCode(), bad);
            }
            assertEquals(405, r.get("/api/trial").statusCode());
            assertEquals(405, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/status")).header("X-Token", r.server.token())
                    .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(404, r.get("/api/nothing").statusCode());
            JsonNode err = JSON.readTree(r.get("/api/nothing").body());
            assertEquals("not_found", err.path("error").asText());
            assertFalse(err.toString().contains("Exception") || err.toString().contains("/Users"), "errors carry no stack traces or paths: " + err);
            assertEquals(0, r.controller.history().size(), "none of the refused calls started a trial");
        }
    }

    @Test
    @Timeout(120)
    void theStatusIsTheEnginesOutcomePassedThroughUnchanged() throws Exception {
        try (Rig r = new Rig(null)) {
            assertEquals(0, r.status().path("trial").path("number").asInt());
            assertEquals("IDLE", r.status().path("decision").path("state").asText());
            AtomicBoolean stop = new AtomicBoolean();
            r.feeder(LiveTrialControllerTest.frames("animate"), stop);
            assertEquals(200, r.post("/api/trial", "{\"label\":\"genuine_live\"}").statusCode());
            JsonNode s = null;
            long t0 = System.currentTimeMillis();
            while (System.currentTimeMillis() - t0 < 60_000) {
                s = r.status();
                if (s.path("decision").path("final").asBoolean()) {
                    break;
                }
                Thread.sleep(100);
            }
            stop.set(true);
            assertTrue(s.path("decision").path("final").asBoolean(), "the trial reached a decision: " + s);
            LiveTrialController.Status engine = r.controller.history().get(0);
            assertEquals(engine.state, s.path("decision").path("state").asText());
            assertEquals(engine.reason, s.path("decision").path("reason").asText());
            assertEquals(engine.verdict, s.path("decision").path("verdict").asText(), "the engine's own wording, unchanged");
            assertEquals("genuine_live", s.path("trial").path("label").asText());
            assertEquals("VERIFIED", s.path("decision").path("state").asText(), "pinned-PAD capture on live-motion frames");
            assertEquals("passed", s.path("stages").get(7).path("state").asText());
            assertEquals(8, s.path("stages").size());
            assertEquals(11, s.path("integrity").size());
            assertTrue(s.path("pad").path("stream").path("median").asDouble() > 0);
            assertTrue(s.path("events").size() >= 3);
            // history carries the same record
            JsonNode h = JSON.readTree(r.get("/api/history").body());
            assertEquals(1, h.size());
            assertEquals("VERIFIED", h.get(0).path("decision").path("state").asText());
            JsonNode info = JSON.readTree(r.get("/api/info").body());
            assertEquals(0.8, info.path("thresholds").path("streamAccept").asDouble(), 1e-6);
            assertTrue(info.path("device").asText().contains("TEST keys"));
        }
    }

    @Test
    @Timeout(60)
    void aSecondTrialStartInsideTheGapIsRateLimitedAndCancelRecordsAnUnfinishedTrial() throws Exception {
        try (Rig r = new Rig(null)) {
            assertEquals(200, r.post("/api/trial", "{\"label\":\"printed_photo\"}").statusCode());
            assertEquals(429, r.post("/api/trial", "{}").statusCode());
            Thread.sleep(300);
            assertEquals(200, r.post("/api/cancel", "{}").statusCode());
            JsonNode s = r.status();
            Thread.sleep(100);
            s = r.status();
            assertEquals("CANCELLED", s.path("decision").path("state").asText());
            assertTrue(s.path("trial").path("unfinished").asBoolean());
            assertFalse(s.path("trial").path("active").asBoolean());
            assertEquals("skipped", s.path("stages").get(7).path("state").asText(), "a cancelled trial is not a decision");
            assertEquals(200, r.post("/api/cancel", "{}").statusCode(), "cancelling again is harmless");
            assertEquals(1, r.controller.history().size());
        }
    }

    @Test
    @Timeout(60)
    void quitCallsBackAndFramesAreServedFromMemoryOnly() throws Exception {
        try (Rig r = new Rig(null)) {
            assertEquals(204, r.get("/api/frame.jpg").statusCode(), "no frame yet is not an error");
            List<byte[]> f = LiveTrialControllerTest.frames("animate");
            r.controller.onStreamFrame(f.get(0));
            HttpResponse<byte[]> img = HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/frame.jpg")).header("X-Token", r.server.token()).build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, img.statusCode());
            assertEquals("image/jpeg", img.headers().firstValue("Content-Type").orElse(""));
            assertEquals("no-store", img.headers().firstValue("Cache-Control").orElse(""));
            assertEquals(f.get(0).length, img.body().length);
            assertEquals(200, r.post("/api/quit", "{}").statusCode());
            long t0 = System.currentTimeMillis();
            while (!r.quit.get() && System.currentTimeMillis() - t0 < 5000) {
                Thread.sleep(20);
            }
            assertTrue(r.quit.get());
        }
    }

    @Test
    @Timeout(60)
    void previewStreamsAreBoundedAndReleasedWhenTheViewerDisconnects() throws Exception {
        try (Rig r = new Rig(null)) {
            AtomicBoolean stop = new AtomicBoolean();
            r.feeder(LiveTrialControllerTest.frames("animate"), stop);
            Thread.sleep(300);
            for (int i = 0; i < 12; i++) {                      // far more sequential viewers than MAX_STREAMS: each is released
                String head = "";
                long t0 = System.currentTimeMillis();
                do {                                            // the server notices a closed viewer within a moment
                    try (Socket s = new Socket("127.0.0.1", r.server.port())) {
                        s.setSoTimeout(5000);
                        s.getOutputStream().write(("GET /api/stream.mjpg?t=" + r.server.token() + " HTTP/1.1\r\nHost: 127.0.0.1:" + r.server.port() + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                        byte[] buf = new byte[2048];
                        int n = s.getInputStream().read(buf);
                        head = new String(buf, 0, Math.max(n, 0), StandardCharsets.ISO_8859_1);
                    }
                    if (head.startsWith("HTTP/1.1 503")) {
                        Thread.sleep(100);
                    }
                } while (head.startsWith("HTTP/1.1 503") && System.currentTimeMillis() - t0 < 4000);
                assertTrue(head.startsWith("HTTP/1.1 200"), "viewer " + i + " was never admitted (slot leaked): " + head);
                assertTrue(head.toLowerCase().contains("multipart/x-mixed-replace"), head);
            }
            // four open viewers fill the limit; the fifth is refused; closing them frees the slots
            Thread.sleep(800);                                   // the last sequential viewer's slot is released
            List<Socket> open = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                Socket s = new Socket("127.0.0.1", r.server.port());
                s.setSoTimeout(5000);
                s.getOutputStream().write(("GET /api/stream.mjpg?t=" + r.server.token() + " HTTP/1.1\r\nHost: 127.0.0.1:" + r.server.port() + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                byte[] b = new byte[64];
                int n = s.getInputStream().read(b);
                assertTrue(new String(b, 0, Math.max(n, 0), StandardCharsets.ISO_8859_1).startsWith("HTTP/1.1 200"), "viewer " + i + " admitted");
                open.add(s);
            }
            Thread.sleep(150);
            assertEquals(503, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/stream.mjpg?t=" + r.server.token())).timeout(java.time.Duration.ofSeconds(5)).build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode(),
                    "the fifth concurrent preview is refused");
            for (Socket s : open) {
                s.close();
            }
            stop.set(true);
            Thread.sleep(1200);                                  // frames have stopped: only the keep-alive can reveal the closed viewers
            HttpResponse<java.io.InputStream> again = HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/api/stream.mjpg?t=" + r.server.token())).timeout(java.time.Duration.ofSeconds(5)).build(),
                    HttpResponse.BodyHandlers.ofInputStream());
            assertEquals(200, again.statusCode(), "slots held by viewers of a stalled camera were freed");
            again.body().close();
            assertEquals(200, r.get("/api/status").statusCode(), "the server stays healthy");
        }
    }

    @Test
    @Timeout(60)
    void concurrentReadersNeverSeeATornSnapshotWhileTheTickerUpdatesIt() throws Exception {
        try (Rig r = new Rig(null)) {
            AtomicBoolean stop = new AtomicBoolean();
            r.feeder(LiveTrialControllerTest.frames("animate"), stop);
            r.post("/api/trial", "{\"label\":\"genuine_live\"}");
            ExecutorService ex = Executors.newFixedThreadPool(8);
            List<Future<Integer>> fs = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                fs.add(ex.submit(() -> {
                    int ok = 0;
                    for (int i = 0; i < 60; i++) {
                        JsonNode j = JSON.readTree(r.get("/api/status").body());          // a torn body would not parse
                        assertEquals(8, j.path("stages").size());
                        assertEquals(11, j.path("integrity").size());
                        ok++;
                    }
                    return ok;
                }));
            }
            for (Future<Integer> f : fs) {
                assertEquals(60, f.get(50, TimeUnit.SECONDS));
            }
            stop.set(true);
            ex.shutdownNow();
        }
    }

    @Test
    void staticFilesAreServedInsideTheUiDirectoryOnly(@TempDir Path tmp) throws Exception {
        Path ui = Files.createDirectory(tmp.resolve("dist"));
        Files.writeString(ui.resolve("index.html"), "<!doctype html><title>ui</title>");
        Files.createDirectory(ui.resolve("assets"));
        Files.writeString(ui.resolve("assets/app.js"), "console.log(1)");
        Files.writeString(tmp.resolve("secret.txt"), "TOP-SECRET");
        try (Rig r = new Rig(ui)) {
            HttpResponse<String> index = HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/")).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, index.statusCode());
            assertTrue(index.body().contains("<title>ui</title>"));
            assertTrue(index.headers().firstValue("Content-Security-Policy").orElse("").contains("default-src 'self'"));
            assertEquals("text/javascript; charset=utf-8", HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/assets/app.js")).build(),
                    HttpResponse.BodyHandlers.ofString()).headers().firstValue("Content-Type").orElse(""));
            assertEquals(200, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/some/client/route")).build(), HttpResponse.BodyHandlers.ofString()).statusCode(),
                    "client-side routes fall back to index.html");
            assertEquals(404, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/missing.js")).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            for (String evil : new String[] {"/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt", "/assets/../../secret.txt", "//..//secret.txt"}) {
                String resp = raw(r.server.port(), "GET " + evil + " HTTP/1.1\r\nHost: 127.0.0.1:" + r.server.port() + "\r\nConnection: close\r\n\r\n");
                assertFalse(resp.contains("TOP-SECRET"), evil + " leaked a file outside the UI directory: " + resp);
            }
        }
        try (Rig r = new Rig(null)) {
            assertEquals(404, HTTP.send(HttpRequest.newBuilder(URI.create(r.base + "/")).build(), HttpResponse.BodyHandlers.ofString()).statusCode(),
                    "without a built UI the API still works and says so");
        }
    }

    @Test
    @Timeout(120)
    void aBurstIsRateLimitedAndSpacedRestartsKeepEveryAbandonedTrialWithoutLeaks() throws Exception {
        try (Rig r = new Rig(null)) {
            int burst = 0;
            for (int i = 0; i < 100; i++) {                       // no pause: the gap rule must hold
                int code = r.post("/api/trial", "{\"label\":\"live\"}").statusCode();
                assertTrue(code == 200 || code == 429, "unexpected " + code);
                if (code == 200) {
                    burst++;
                }
            }
            assertTrue(burst >= 1 && burst < 100, "the burst was limited: " + burst);
            int spaced = 0;
            for (int i = 0; i < 25; i++) {                        // just over the gap: every start is accepted and the previous trial is kept
                Thread.sleep(270);
                assertEquals(200, r.post("/api/trial", "{\"label\":\"photo\"}").statusCode());
                spaced++;
            }
            long workers = Thread.getAllStackTraces().keySet().stream().filter(t -> t.isAlive() && "liveness-worker".equals(t.getName())).count();
            assertTrue(workers <= 1, "workers: " + workers);
            assertEquals(burst + spaced - 1, r.controller.history().size(), "every abandoned trial is recorded, none dropped");
            assertEquals(200, r.get("/api/status").statusCode());
        }
    }
}
