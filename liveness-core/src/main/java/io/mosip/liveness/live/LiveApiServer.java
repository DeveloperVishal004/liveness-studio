package io.mosip.liveness.live;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Minimal LOCAL HTTP API around {@link LiveTrialController} for a browser frontend (docs/frontend/LOCAL_API_DESIGN.md).
 *
 * <p>The server adds no decisions: every decision, reason and score is the engine's, passed through
 * {@link LiveSnapshot}. One ticker thread is the only caller of {@code controller.poll()} (which advances the session and
 * triggers the signed capture); request handlers only read a cached snapshot or issue start/cancel/quit.
 *
 * <p>Security: bound to loopback only; the {@code Host} header must be loopback:port (DNS-rebinding defence); mutating
 * calls must be same-origin (no foreign {@code Origin}); every {@code /api} call needs a random per-launch token
 * (header {@code X-Token} or query {@code t}, constant-time compare); request bodies are capped; trial starts are rate
 * limited; errors carry a code and a short message, never a stack trace or a path. Frames are served from memory and
 * never written or logged.
 */
public final class LiveApiServer implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_BODY = 4096;
    private static final long MIN_TRIAL_GAP_MS = 250;
    private static final int MAX_STREAMS = 4;
    private static final Pattern LABEL = Pattern.compile("^[a-z][a-z0-9_]{0,31}$");

    private final LiveTrialController controller;
    private final LiveSnapshot.Thresholds thresholds;
    private final String cameraDescription;
    private final Path uiDir;
    private final Runnable onQuit;
    private final String token;
    private final HttpServer server;
    private final ScheduledExecutorService ticker = Executors.newSingleThreadScheduledExecutor(r -> daemon(r, "live-api-ticker"));
    private final ExecutorService pool = Executors.newFixedThreadPool(8, r -> daemon(r, "live-api-http"));
    private final AtomicInteger streams = new AtomicInteger();
    private volatile boolean closed;
    private volatile byte[] cachedStatus = "{}".getBytes(StandardCharsets.UTF_8);
    private long lastTrialStart;
    private final int port;

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    /**
     * @param port  0 = pick a free port
     * @param token null = generate a random token
     * @param uiDir directory of the built frontend, or null to serve the API only
     */
    public LiveApiServer(LiveTrialController controller, LiveSnapshot.Thresholds thresholds, String cameraDescription, Path uiDir,
                         int port, String token, Runnable onQuit) throws IOException {
        this.controller = controller;
        this.thresholds = thresholds;
        this.cameraDescription = cameraDescription;
        this.uiDir = uiDir == null ? null : uiDir.toAbsolutePath().normalize();
        this.onQuit = onQuit == null ? () -> { } : onQuit;
        this.token = token != null ? token : randomToken();
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 32);
        this.port = server.getAddress().getPort();
        server.setExecutor(pool);
        server.createContext("/", this::route);
    }

    private static String randomToken() {
        byte[] b = new byte[24];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    public int port() {
        return port;
    }

    public String token() {
        return token;
    }

    public String url() {
        return "http://127.0.0.1:" + port + "/#t=" + token;
    }

    public void start() {
        ticker.scheduleWithFixedDelay(() -> {
            try {
                LiveTrialController.Status s = controller.poll();       // the ONLY poll() caller: advances the session
                cachedStatus = JSON.writeValueAsBytes(LiveSnapshot.toJson(s, thresholds, controller.framesReceived(), controller.lastFrameAgeMs()));
            } catch (Throwable t) {
                // never let a tick failure stop the loop; the last good snapshot stays
            }
        }, 0, 33, TimeUnit.MILLISECONDS);
        server.start();
    }

    @Override
    public void close() {
        closed = true;
        ticker.shutdownNow();
        try {
            ticker.awaitTermination(3, TimeUnit.SECONDS);               // the ticker must stop before the models close
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        server.stop(0);
        pool.shutdownNow();
    }

    // ---- routing ----------------------------------------------------------------------------------------------------------
    private void route(HttpExchange ex) throws IOException {
        try {
            if (!hostOk(ex)) {
                error(ex, 403, "forbidden_host", "Unexpected Host header.");
                return;
            }
            String path = ex.getRequestURI().getPath();
            if (path.startsWith("/api/")) {
                api(ex, path);
            } else {
                staticFile(ex, path);
            }
        } catch (Throwable t) {
            try {
                error(ex, 500, "internal_error", "The request could not be processed.");
            } catch (Throwable ignored) {
                // the connection is already gone
            }
        } finally {
            ex.close();
        }
    }

    private boolean hostOk(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Host");
        return h != null && (h.equals("127.0.0.1:" + port) || h.equals("localhost:" + port));
    }

    private boolean originOk(HttpExchange ex) {
        String o = ex.getRequestHeaders().getFirst("Origin");
        return o == null || o.equals("http://127.0.0.1:" + port) || o.equals("http://localhost:" + port);
    }

    private boolean tokenOk(HttpExchange ex) {
        String given = ex.getRequestHeaders().getFirst("X-Token");
        if (given == null) {
            String q = ex.getRequestURI().getRawQuery();
            if (q != null) {
                for (String kv : q.split("&")) {
                    if (kv.startsWith("t=")) {
                        given = kv.substring(2);
                    }
                }
            }
        }
        return given != null && MessageDigest.isEqual(given.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8));
    }

    private void api(HttpExchange ex, String path) throws IOException {
        if (!tokenOk(ex)) {
            error(ex, 401, "unauthorized", "A valid token is required.");
            return;
        }
        String method = ex.getRequestMethod();
        switch (path) {
            case "/api/status":
                get(ex, method, () -> json(ex, 200, cachedStatus));
                return;
            case "/api/info":
                get(ex, method, () -> json(ex, 200, JSON.writeValueAsBytes(LiveSnapshot.info(thresholds, cameraDescription))));
                return;
            case "/api/history":
                get(ex, method, () -> {
                    List<Map<String, Object>> out = new ArrayList<>();
                    for (LiveTrialController.Status s : controller.history()) {
                        out.add(LiveSnapshot.toJson(s, thresholds, controller.framesReceived(), controller.lastFrameAgeMs()));
                    }
                    json(ex, 200, JSON.writeValueAsBytes(out));
                });
                return;
            case "/api/frame.jpg":
                get(ex, method, () -> frame(ex));
                return;
            case "/api/stream.mjpg":
                get(ex, method, () -> mjpeg(ex));
                return;
            case "/api/trial":
                post(ex, method, () -> startTrial(ex));
                return;
            case "/api/cancel":
                post(ex, method, () -> {
                    readBody(ex);
                    controller.cancelTrial();
                    json(ex, 200, "{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
                });
                return;
            case "/api/quit":
                post(ex, method, () -> {
                    readBody(ex);
                    json(ex, 200, "{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
                    new Thread(onQuit, "live-api-quit").start();
                });
                return;
            default:
                error(ex, 404, "not_found", "Unknown endpoint.");
        }
    }

    private interface Action {
        void run() throws Exception;
    }

    private void get(HttpExchange ex, String method, Action a) throws IOException {
        if (!"GET".equals(method)) {
            ex.getResponseHeaders().set("Allow", "GET");
            error(ex, 405, "method_not_allowed", "Use GET.");
            return;
        }
        try {
            a.run();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            error(ex, 500, "internal_error", "The request could not be processed.");
        }
    }

    private void post(HttpExchange ex, String method, Action a) throws IOException {
        if (!"POST".equals(method)) {
            ex.getResponseHeaders().set("Allow", "POST");
            error(ex, 405, "method_not_allowed", "Use POST.");
            return;
        }
        if (!originOk(ex)) {
            error(ex, 403, "forbidden_origin", "Cross-origin requests are not accepted.");
            return;
        }
        try {
            a.run();
        } catch (BodyTooLarge e) {
            error(ex, 413, "body_too_large", "Request body is too large.");
        } catch (BadRequest e) {
            error(ex, 400, "bad_request", e.getMessage());
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            error(ex, 500, "internal_error", "The request could not be processed.");
        }
    }

    private static final class BodyTooLarge extends Exception { }

    private static final class BadRequest extends Exception {
        BadRequest(String m) {
            super(m);
        }
    }

    private byte[] readBody(HttpExchange ex) throws IOException, BodyTooLarge {
        try (InputStream in = ex.getRequestBody()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > MAX_BODY) {
                    throw new BodyTooLarge();
                }
            }
            return out.toByteArray();
        }
    }

    private void startTrial(HttpExchange ex) throws Exception {
        byte[] body = readBody(ex);
        String label = null;
        if (body.length > 0) {
            Map<?, ?> req;
            try {
                req = JSON.readValue(body, Map.class);
            } catch (Exception e) {
                throw new BadRequest("Body must be JSON.");
            }
            Object l = req.get("label");
            if (l != null) {
                if (!(l instanceof String) || !LABEL.matcher((String) l).matches()) {
                    throw new BadRequest("label must be lowercase letters, digits or underscores (max 32).");
                }
                label = (String) l;
            }
        }
        synchronized (this) {
            long now = System.currentTimeMillis();
            if (now - lastTrialStart < MIN_TRIAL_GAP_MS) {
                error(ex, 429, "too_many_requests", "Wait a moment before starting another trial.");
                return;
            }
            lastTrialStart = now;
        }
        controller.startTrial(label);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        json(ex, 200, JSON.writeValueAsBytes(out));
    }

    private void frame(HttpExchange ex) throws IOException {
        byte[] f = controller.latestFrame();
        if (f == null) {
            ex.sendResponseHeaders(204, -1);
            return;
        }
        ex.getResponseHeaders().set("Content-Type", "image/jpeg");
        security(ex);
        ex.sendResponseHeaders(200, f.length);
        try (OutputStream o = ex.getResponseBody()) {
            o.write(f);
        }
    }

    private void mjpeg(HttpExchange ex) throws IOException {
        if (streams.incrementAndGet() > MAX_STREAMS) {
            streams.decrementAndGet();
            error(ex, 503, "too_many_streams", "Too many open previews.");
            return;
        }
        try {
            ex.getResponseHeaders().set("Content-Type", "multipart/x-mixed-replace; boundary=frame");
            security(ex);
            ex.sendResponseHeaders(200, 0);
            OutputStream o = ex.getResponseBody();
            byte[] last = null;
            long lastWrite = System.nanoTime();
            while (!closed) {
                byte[] f = controller.latestFrame();
                if (f != null && f != last) {
                    last = f;
                    o.write(("--frame\r\nContent-Type: image/jpeg\r\nContent-Length: " + f.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    o.write(f);
                    o.write("\r\n".getBytes(StandardCharsets.US_ASCII));
                    o.flush();
                    lastWrite = System.nanoTime();
                } else if (System.nanoTime() - lastWrite > 500_000_000L) {
                    o.write("\r\n".getBytes(StandardCharsets.US_ASCII));   // keep-alive: a stalled camera must not hide a closed viewer
                    o.flush();
                    lastWrite = System.nanoTime();
                }
                Thread.sleep(33);
            }
        } catch (IOException | InterruptedException e) {
            // the viewer closed the preview: normal
        } finally {
            streams.decrementAndGet();
        }
    }

    // ---- static frontend ----------------------------------------------------------------------------------------------------
    private void staticFile(HttpExchange ex, String path) throws IOException {
        if (!"GET".equals(ex.getRequestMethod()) && !"HEAD".equals(ex.getRequestMethod())) {
            ex.getResponseHeaders().set("Allow", "GET, HEAD");
            error(ex, 405, "method_not_allowed", "Use GET.");
            return;
        }
        if (uiDir == null) {
            error(ex, 404, "no_ui", "The frontend is not built. Run: cd frontend && npm install && npm run build");
            return;
        }
        String rel = path.equals("/") ? "index.html" : path.substring(1);
        Path file = uiDir.resolve(rel).normalize();
        if (!file.startsWith(uiDir)) {
            error(ex, 403, "forbidden", "Not allowed.");
            return;
        }
        if (!Files.isRegularFile(file)) {
            if (rel.contains(".")) {
                error(ex, 404, "not_found", "Not found.");
                return;
            }
            file = uiDir.resolve("index.html");                         // client-side routes
            if (!Files.isRegularFile(file)) {
                error(ex, 404, "no_ui", "The frontend is not built.");
                return;
            }
        }
        byte[] data = Files.readAllBytes(file);
        ex.getResponseHeaders().set("Content-Type", contentType(file.getFileName().toString()));
        ex.getResponseHeaders().set("Cache-Control", file.getFileName().toString().equals("index.html") ? "no-store" : "public, max-age=3600");
        security(ex);
        ex.getResponseHeaders().set("Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; "
                        + "script-src 'self'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
        ex.sendResponseHeaders(200, "HEAD".equals(ex.getRequestMethod()) ? -1 : data.length);
        if (!"HEAD".equals(ex.getRequestMethod())) {
            try (OutputStream o = ex.getResponseBody()) {
                o.write(data);
            }
        }
    }

    private static String contentType(String name) {
        String n = name.toLowerCase();
        if (n.endsWith(".html")) return "text/html; charset=utf-8";
        if (n.endsWith(".js") || n.endsWith(".mjs")) return "text/javascript; charset=utf-8";
        if (n.endsWith(".css")) return "text/css; charset=utf-8";
        if (n.endsWith(".svg")) return "image/svg+xml";
        if (n.endsWith(".woff2")) return "font/woff2";
        if (n.endsWith(".woff")) return "font/woff";
        if (n.endsWith(".png")) return "image/png";
        if (n.endsWith(".ico")) return "image/x-icon";
        if (n.endsWith(".json") || n.endsWith(".map")) return "application/json";
        return "application/octet-stream";
    }

    // ---- responses ----------------------------------------------------------------------------------------------------------
    private static void security(HttpExchange ex) {
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.getResponseHeaders().set("Referrer-Policy", "no-referrer");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
    }

    private void json(HttpExchange ex, int code, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        security(ex);
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream o = ex.getResponseBody()) {
            o.write(body);
        }
    }

    private void error(HttpExchange ex, int code, String error, String message) throws IOException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", error);
        m.put("message", message);
        json(ex, code, JSON.writeValueAsBytes(m));
    }
}
