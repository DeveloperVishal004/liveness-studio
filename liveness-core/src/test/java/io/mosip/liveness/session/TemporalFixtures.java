package io.mosip.liveness.session;

import io.mosip.liveness.frame.EncodedFrame;
import io.mosip.liveness.pipeline.FramePipeline;
import io.mosip.liveness.vision.Phase0Models;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Runs the real pipeline over research/fixtures/temporal sequences ([SIM] fixtures) and returns evidence records. */
final class TemporalFixtures {
    private TemporalFixtures() {}

    static Path root() {
        return Paths.get(System.getProperty("phase0.root", "..")).toAbsolutePath().normalize();
    }

    static List<EvidenceRecord> records(Phase0Models models, String kind, String source) throws Exception {
        Path dir = root().resolve("research/fixtures/temporal").resolve(kind).resolve(source);
        List<Path> files;
        try (Stream<Path> s = Files.list(dir)) {
            files = s.filter(p -> p.toString().endsWith(".jpg")).sorted().collect(Collectors.toList());
        }
        FramePipeline.Config cfg = new FramePipeline.Config();
        cfg.embedEvery = 0;
        List<EvidenceRecord> out = new ArrayList<>();
        try (FramePipeline p = new FramePipeline(models, cfg)) {
            long seq = 0;
            for (Path f : files) {
                long t = seq * 66_666_667L;   // 15 fps timeline
                FramePipeline.FrameEvidence ev = p.process(new EncodedFrame(seq, t, 0, "image/jpeg", Files.readAllBytes(f)));
                out.add(new EvidenceRecord(1, seq, t, 0, ev.faceCount, ev.eligible, ev.ineligibleReason, ev.padFused,
                        ev.landmarks, ev.faceBox, ev.alignedGrey, ev.yawProxy));
                seq++;
            }
        }
        return out;
    }
}
