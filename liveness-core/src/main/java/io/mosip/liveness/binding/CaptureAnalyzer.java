package io.mosip.liveness.binding;

import io.mosip.liveness.vision.BgrImage;

/** Vision analysis of the signed capture image; separated from {@link CaptureBinder} so binding logic is testable. */
public interface CaptureAnalyzer {

    /** Result of analysing one image. {@code embedding} and {@code padRealProbability} are null when faceCount != 1. */
    final class Analysis {
        public final int faceCount;
        public final Float padRealProbability;
        public final float[] embedding;

        public Analysis(int faceCount, Float padRealProbability, float[] embedding) {
            this.faceCount = faceCount;
            this.padRealProbability = padRealProbability;
            this.embedding = embedding;
        }
    }

    /**
     * Analyses the image. Must throw (never return a default) if a model fails or produces invalid output, so
     * that an engine error can never be mistaken for a passing score (invariant I2).
     */
    Analysis analyze(BgrImage image) throws Exception;
}
