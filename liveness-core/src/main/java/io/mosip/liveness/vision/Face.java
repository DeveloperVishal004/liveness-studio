package io.mosip.liveness.vision;

/** A detected face: box (x, y, w, h) and 5 landmarks (right eye, left eye, nose, right mouth, left mouth). */
public final class Face {
    public final float x, y, w, h;
    public final float[][] landmarks;
    public final float score;

    public Face(float x, float y, float w, float h, float[][] landmarks, float score) {
        this.x = x;
        this.y = y;
        this.w = w;
        this.h = h;
        this.landmarks = landmarks;
        this.score = score;
    }

    public float iou(Face o) {
        float ix = Math.max(0f, Math.min(x + w, o.x + o.w) - Math.max(x, o.x));
        float iy = Math.max(0f, Math.min(y + h, o.y + o.h) - Math.max(y, o.y));
        float inter = ix * iy;
        float union = w * h + o.w * o.h - inter;
        return union > 0 ? inter / union : 0f;
    }

    public float area() { return w * h; }
}
