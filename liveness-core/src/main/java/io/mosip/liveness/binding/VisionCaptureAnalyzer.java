package io.mosip.liveness.binding;

import io.mosip.liveness.vision.BgrImage;
import io.mosip.liveness.vision.Face;
import io.mosip.liveness.vision.MiniFasPad;
import io.mosip.liveness.vision.Phase0Models;

import java.util.List;

/** {@link CaptureAnalyzer} backed by the Phase-0 models (YuNet + MiniFASNet + SFace). */
public final class VisionCaptureAnalyzer implements CaptureAnalyzer {
    private final Phase0Models models;

    public VisionCaptureAnalyzer(Phase0Models models) {
        this.models = models;
    }

    @Override
    public synchronized Analysis analyze(BgrImage image) throws Exception {
        List<Face> faces = models.detector.detect(image);
        if (faces.size() != 1) {
            return new Analysis(faces.size(), null, null);
        }
        Face f = faces.get(0);
        float pad = MiniFasPad.fuse(models.pad.score(image, f));
        float[] emb = models.embedder.embed(image, f);
        return new Analysis(1, pad, emb);
    }
}
