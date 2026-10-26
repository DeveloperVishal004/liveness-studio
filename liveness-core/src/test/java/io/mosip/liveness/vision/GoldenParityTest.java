package io.mosip.liveness.vision;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Java pipeline vs the Python reference (research/reference_pipeline.py) on the same JPEG files.
 * Differences come from (a) JPEG decoders (ImageIO vs libjpeg-turbo) and (b) 8-bit resize/warp arithmetic.
 * Tolerances are what a PAD decision can absorb; the measured maxima are printed for the Phase-0 report.
 */
class GoldenParityTest {
    static Path root;
    static Phase0Models models;
    static JsonNode golden;

    @BeforeAll
    static void load() throws Exception {
        root = Paths.get(System.getProperty("phase0.root", "..")).toAbsolutePath().normalize();
        models = Phase0Models.load(root, 1, 320, false);
        golden = new ObjectMapper().readTree(root.resolve("research/fixtures/golden/golden.json").toFile());
    }

    @AfterAll
    static void close() throws Exception {
        models.close();
    }

    @Test
    void detectionPadAndEmbeddingMatchPythonReference() throws Exception {
        ImageDecoder dec = new ImageDecoder();
        double worstIou = 1, worstPad = 0, worstCos = 1, worstLm = 0, worstPadSameBox = 0;
        int compared = 0;
        for (JsonNode rec : golden.path("records")) {
            BgrImage img = dec.decode(Files.readAllBytes(root.resolve("research/fixtures/golden").resolve(rec.path("file").asText())));
            List<Face> faces = models.detector.detect(img);
            assertEquals(rec.path("faces").size(), faces.size(), "face count for " + rec.path("file").asText());
            if (faces.isEmpty()) {
                continue;
            }
            JsonNode gf = rec.path("faces").get(0);
            JsonNode b = gf.path("box");
            Face g = new Face((float) b.get(0).asDouble(), (float) b.get(1).asDouble(), (float) b.get(2).asDouble(),
                    (float) b.get(3).asDouble(), null, 0);
            Face f = faces.get(0);
            worstIou = Math.min(worstIou, f.iou(g));
            for (int k = 0; k < 5; k++) {
                worstLm = Math.max(worstLm, Math.abs(f.landmarks[k][0] - gf.path("kps").get(k).get(0).asDouble()));
                worstLm = Math.max(worstLm, Math.abs(f.landmarks[k][1] - gf.path("kps").get(k).get(1).asDouble()));
            }
            Map<Float, Float> pad = models.pad.score(img, f);
            worstPad = Math.max(worstPad, Math.abs(pad.get(2.7f) - rec.path("pad").path("2.7").asDouble()));
            worstPad = Math.max(worstPad, Math.abs(pad.get(4.0f) - rec.path("pad").path("4.0").asDouble()));
            // Same PAD, but on the Python detector's box: isolates resize arithmetic from box differences.
            Map<Float, Float> padOnRefBox = models.pad.score(img, g);
            worstPadSameBox = Math.max(worstPadSameBox, Math.abs(padOnRefBox.get(2.7f) - rec.path("pad").path("2.7").asDouble()));
            worstPadSameBox = Math.max(worstPadSameBox, Math.abs(padOnRefBox.get(4.0f) - rec.path("pad").path("4.0").asDouble()));
            float[] e = models.embedder.embed(img, f);
            JsonNode ge = rec.path("embedding");
            double dot = 0;
            for (int i = 0; i < e.length; i++) {
                dot += e[i] * ge.get(i).asDouble();
            }
            worstCos = Math.min(worstCos, dot);
            compared++;
        }
        System.out.printf("GOLDEN PARITY over %d faces: worst IoU=%.4f, worst landmark err=%.2fpx, worst |dPAD|=%.4f "
                        + "(same box: %.4f), worst emb cos=%.4f%n",
                compared, worstIou, worstLm, worstPad, worstPadSameBox, worstCos);
        assertTrue(compared >= 15);
        assertTrue(worstIou >= 0.95, "IoU " + worstIou);
        assertTrue(worstLm <= 3.0, "landmarks " + worstLm);
        assertTrue(worstPad <= 0.05, "PAD delta " + worstPad);
        assertTrue(worstCos >= 0.98, "embedding cosine " + worstCos);
    }

    @Test
    void jpegDecoderDifferenceIsSmall() throws Exception {
        JsonNode first = golden.path("records").get(0);
        Path dir = root.resolve("research/fixtures/golden");
        BgrImage j = new ImageDecoder().decode(Files.readAllBytes(dir.resolve(first.path("file").asText())));
        byte[] cv = Files.readAllBytes(dir.resolve(first.path("file").asText() + ".cv2.bgr"));
        assertEquals(cv.length, j.data.length);
        long sum = 0;
        int max = 0;
        for (int i = 0; i < cv.length; i++) {
            int d = Math.abs((cv[i] & 0xFF) - (j.data[i] & 0xFF));
            sum += d;
            max = Math.max(max, d);
        }
        double mean = (double) sum / cv.length;
        System.out.printf("JPEG DECODER ImageIO vs OpenCV: mean |d|=%.3f, max |d|=%d (0..255)%n", mean, max);
        assertTrue(mean < 2.0, "mean decoder difference " + mean);
    }
}
