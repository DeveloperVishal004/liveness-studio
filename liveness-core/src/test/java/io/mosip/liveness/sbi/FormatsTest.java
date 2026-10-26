package io.mosip.liveness.sbi;

import io.mosip.liveness.vision.BgrImage;
import io.mosip.liveness.vision.ImageDecoder;
import org.junit.jupiter.api.Test;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.MemoryCacheImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FormatsTest {

    static byte[] resource(String name) throws Exception {
        try (InputStream in = FormatsTest.class.getResourceAsStream(name)) {
            return in.readAllBytes();
        }
    }

    @Test
    void parsesMosipMockMdsFaceIsoAndDecodesItsJpeg2000() throws Exception {
        byte[] iso = resource("/mosip/Face.iso");
        Iso19794FaceRecord rec = Iso19794FaceRecord.parse(iso);
        assertEquals(240, rec.width);
        assertEquals(320, rec.height);
        assertEquals(Iso19794FaceRecord.TYPE_JPEG2000_LOSSLESS, rec.imageDataType);
        assertEquals(2022, rec.captureYear);
        BgrImage img = new ImageDecoder().decode(rec.imageData);   // exercises jai-imageio-jpeg2000
        assertEquals(240, img.width);
        assertEquals(320, img.height);
    }

    @Test
    void rejectsTruncatedOrInconsistentRecords() throws Exception {
        byte[] iso = resource("/mosip/Face.iso");
        assertThrows(IllegalArgumentException.class, () -> Iso19794FaceRecord.parse(Arrays.copyOf(iso, iso.length - 1)));
        byte[] wrongFormat = iso.clone();
        wrongFormat[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> Iso19794FaceRecord.parse(wrongFormat));
        byte[] badLen = iso.clone();
        badLen[72] ^= 0x01;   // image data length low byte
        assertThrows(IllegalArgumentException.class, () -> Iso19794FaceRecord.parse(badLen));
        assertThrows(IllegalArgumentException.class, () -> Iso19794FaceRecord.parse(new byte[10]));
    }

    @Test
    void jpegQualityEstimateTracksEncoderQuality() throws Exception {
        BufferedImage img = new BufferedImage(64, 48, BufferedImage.TYPE_3BYTE_BGR);
        for (int q : new int[] {30, 50, 75, 90}) {
            byte[] jpg = encode(img, q / 100f);
            JpegInfo info = JpegInfo.parse(jpg);
            assertEquals(64, info.width);
            assertEquals(48, info.height);
            assertTrue(Math.abs(info.estimatedQuality - q) <= 2, "q=" + q + " est=" + info.estimatedQuality);
            assertEquals("4:2:0", info.chroma); // ImageIO's default JPEG writer subsamples chroma 2x2
        }
    }

    @Test
    void detectsExifOrientationThatDecodersDisagreeOn() throws Exception {
        java.nio.file.Path root = java.nio.file.Paths.get(System.getProperty("phase0.root", ".."));
        byte[] tagged = java.nio.file.Files.readAllBytes(root.resolve("research/fixtures/minivision/image_T1.jpg"));
        assertEquals(6, JpegInfo.parse(tagged).exifOrientation);   // OpenCV rotates this file, ImageIO does not
        byte[] plain = encode(new BufferedImage(8, 8, BufferedImage.TYPE_3BYTE_BGR), 0.9f);
        assertEquals(0, JpegInfo.parse(plain).exifOrientation);
    }

    @Test
    void decoderRejectsDecompressionBombs() throws Exception {
        byte[] jpg = encode(new BufferedImage(200, 200, BufferedImage.TYPE_3BYTE_BGR), 0.8f);
        assertThrows(java.io.IOException.class, () -> new ImageDecoder(100 * 100).decode(jpg));
    }

    static byte[] encode(BufferedImage img, float quality) throws Exception {
        ImageWriter w = ImageIO.getImageWritersByFormatName("jpeg").next();
        ImageWriteParam p = w.getDefaultWriteParam();
        p.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        p.setCompressionQuality(quality);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (MemoryCacheImageOutputStream out = new MemoryCacheImageOutputStream(bos)) {
            w.setOutput(out);
            w.write(null, new IIOImage(img, null, null), p);
        }
        w.dispose();
        return bos.toByteArray();
    }
}
