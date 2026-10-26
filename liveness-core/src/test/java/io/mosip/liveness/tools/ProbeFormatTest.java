package io.mosip.liveness.tools;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProbeFormatTest {

    @Test
    void classifiesSbiTimestampFormats() {
        assertEquals("yyyy-MM-ddTHH:mm:ssZ (SBI spec)", SbiProbe.timestampFormat("2026-10-24T10:00:00Z"));
        assertTrue(SbiProbe.timestampFormat("2026-10-24T10:00:00.123Z").startsWith("yyyy-MM-ddTHH:mm:ss.fffZ"));
        assertTrue(SbiProbe.timestampFormat("2026-10-24T15:30:00+05:30").startsWith("ISO-8601 with offset"));
        assertEquals("other: 99/99/9999", SbiProbe.timestampFormat("24/10/2026"));
        assertEquals("missing", SbiProbe.timestampFormat(null));
    }

    @Test
    void cliRejectsUnknownOrMalformedOptions() {
        assertThrows(IllegalArgumentException.class, () -> new Phase0Cli.Args(new String[] {"--threads 1"}));
        assertThrows(IllegalArgumentException.class, () -> new Phase0Cli.Args(new String[] {"--thread", "1"}));
        assertEquals(1, new Phase0Cli.Args(new String[] {"--threads", "1"}).getInt("threads", 2));
    }
}
