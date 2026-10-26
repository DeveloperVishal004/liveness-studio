package io.mosip.liveness.vision;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;

/**
 * Decodes JPEG (stream frames) and JPEG 2000 (ISO 19794-5 captures) into {@link BgrImage}.
 *
 * <p>Uses ImageIO; JPEG 2000 support comes from {@code jai-imageio-jpeg2000}, the decoder the Registration
 * Client already ships. Dimensions are checked before full decode to bound memory (decompression-bomb guard).
 */
public final class ImageDecoder {
    private final int maxPixels;

    public ImageDecoder() {
        this(4096 * 4096);
    }

    public ImageDecoder(int maxPixels) {
        this.maxPixels = maxPixels;
        ImageIO.setUseCache(false); // never spill biometric pixels to a temp file
    }

    public BgrImage decode(byte[] encoded) throws IOException {
        try (ImageInputStream in = ImageIO.createImageInputStream(new ByteArrayInputStream(encoded))) {
            Iterator<ImageReader> readers = ImageIO.getImageReaders(in);
            if (!readers.hasNext()) {
                throw new IOException("no ImageIO reader for this format");
            }
            ImageReader r = readers.next();
            try {
                r.setInput(in, true, true);
                long px = (long) r.getWidth(0) * r.getHeight(0);
                if (px <= 0 || px > maxPixels) {
                    throw new IOException("image too large: " + r.getWidth(0) + "x" + r.getHeight(0));
                }
                return toBgr(r.read(0));
            } finally {
                r.dispose();
            }
        }
    }

    static BgrImage toBgr(BufferedImage img) {
        int w = img.getWidth();
        int h = img.getHeight();
        if (img.getType() == BufferedImage.TYPE_3BYTE_BGR) {
            byte[] src = ((DataBufferByte) img.getRaster().getDataBuffer()).getData();
            if (src.length == w * h * 3) {
                return new BgrImage(w, h, src); // ImageIO's buffer is already OpenCV-ordered BGR
            }
        }
        byte[] out = new byte[w * h * 3];
        int[] row = new int[w];
        for (int y = 0; y < h; y++) {
            img.getRGB(0, y, w, 1, row, 0, w);
            int o = y * w * 3;
            for (int x = 0; x < w; x++) {
                int p = row[x];
                out[o++] = (byte) p;          // B
                out[o++] = (byte) (p >> 8);   // G
                out[o++] = (byte) (p >> 16);  // R
            }
        }
        return new BgrImage(w, h, out);
    }
}
