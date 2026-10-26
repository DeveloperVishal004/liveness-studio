package io.mosip.liveness.vision;

/** 8-bit interleaved BGR image (OpenCV memory layout), row-major, no padding. */
public final class BgrImage {
    public final int width;
    public final int height;
    public final byte[] data;

    public BgrImage(int width, int height, byte[] data) {
        if (width <= 0 || height <= 0 || data.length != width * height * 3) {
            throw new IllegalArgumentException("bad image geometry " + width + "x" + height + " len=" + data.length);
        }
        this.width = width;
        this.height = height;
        this.data = data;
    }

    public int get(int x, int y, int c) {
        return data[(y * width + x) * 3 + c] & 0xFF;
    }
}
