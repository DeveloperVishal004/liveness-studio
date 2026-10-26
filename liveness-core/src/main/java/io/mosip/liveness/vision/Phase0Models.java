package io.mosip.liveness.vision;

import ai.onnxruntime.OrtException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Loads the Phase-0 model set from {@code <root>/models} and verifies each file against
 * {@code models/onnx/manifest.json} (SHA-256). A missing or mismatching hash refuses to load (fail closed).
 * In production this becomes the signed model bundle described in the architecture (section 16).
 */
public final class Phase0Models implements AutoCloseable {
    public final YuNetDetector detector;
    public final MiniFasPad pad;
    public final SFaceEmbedder embedder;
    public final Map<String, String> versions;

    private Phase0Models(YuNetDetector d, MiniFasPad p, SFaceEmbedder e, Map<String, String> versions) {
        this.detector = d;
        this.pad = p;
        this.embedder = e;
        this.versions = versions;
    }

    public static Phase0Models load(Path root, int threads, int detWidth, boolean int8Pad) throws IOException, OrtException {
        Path models = root.resolve("models");
        JsonNode manifest = new ObjectMapper().readTree(models.resolve("onnx/manifest.json").toFile());
        Map<String, String> versions = new LinkedHashMap<>();
        YuNetDetector det = new YuNetDetector(open(models, manifest, "yunet", threads, versions), detWidth, 0.6f, 0.3f);
        Map<Float, ai.onnxruntime.OrtSession> pads = new LinkedHashMap<>();
        String suffix = int8Pad ? "_int8" : "";
        pads.put(2.7f, open(models, manifest, "minifasnet_s2.7" + suffix, threads, versions));
        pads.put(4.0f, open(models, manifest, "minifasnet_s4.0" + suffix, threads, versions));
        SFaceEmbedder emb = new SFaceEmbedder(open(models, manifest, "sface", threads, versions));
        return new Phase0Models(det, new MiniFasPad(pads), emb, versions);
    }

    private static ai.onnxruntime.OrtSession open(Path models, JsonNode manifest, String key, int threads,
                                                   Map<String, String> versions) throws IOException, OrtException {
        JsonNode e = manifest.path(key);
        if (e.isMissingNode()) {
            throw new IOException("model '" + key + "' not in manifest");
        }
        Path p = models.resolve(e.path("path").asText());
        if (!Files.isRegularFile(p)) {
            throw new IOException("model file missing: " + p);
        }
        String sha = e.path("sha256").asText();
        versions.put(key, sha.substring(0, 12));
        return OrtModels.open(p, threads, sha);
    }

    @Override
    public void close() throws OrtException {
        detector.close();
        pad.close();
        embedder.close();
    }
}
