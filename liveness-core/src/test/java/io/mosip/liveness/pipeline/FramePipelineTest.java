package io.mosip.liveness.pipeline;

import io.mosip.liveness.frame.EncodedFrame;
import io.mosip.liveness.vision.Phase0Models;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FramePipelineTest {

    @Test
    void frozenFramesAreNeverEvidenceButFreshFramesAre() throws Exception {
        Path root = Paths.get(System.getProperty("phase0.root", "..")).toAbsolutePath().normalize();
        byte[] a = Files.readAllBytes(root.resolve("research/fixtures/golden/g02_image_T1.jpg"));
        byte[] b = Files.readAllBytes(root.resolve("research/fixtures/golden/g00_image_F1.jpg"));
        FramePipeline.Config cfg = new FramePipeline.Config();
        cfg.embedEvery = 0;
        try (Phase0Models m = Phase0Models.load(root, 1, 320, false); FramePipeline p = new FramePipeline(m, cfg)) {
            FramePipeline.FrameEvidence first = p.process(new EncodedFrame(1, 1, 0, "image/jpeg", a));
            assertTrue(first.eligible, String.valueOf(first.ineligibleReason));
            FramePipeline.FrameEvidence repeat = p.process(new EncodedFrame(2, 2, 0, "image/jpeg", a.clone()));
            assertFalse(repeat.eligible);
            assertEquals("FROZEN_FRAME", repeat.ineligibleReason);
            assertNull(repeat.padFused);
            FramePipeline.FrameEvidence other = p.process(new EncodedFrame(3, 3, 0, "image/jpeg", b));
            assertEquals(1, other.faceCount);
        }
    }
}
