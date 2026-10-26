package io.mosip.liveness.binding;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Guards that a B1 statement does not break UNMODIFIED desktop Registration Clients. Mirrors the field shapes of
 * {@code SbiRCaptureResponseDTO} / {@code SbiRCaptureResponseBiometricsDTO} (registration-client develop @ e9ff40b,
 * Lombok @Data, no ignoreUnknown) and the client's parse call ({@code new ObjectMapper().readValue(...)} in
 * {@code MosipDeviceSpecification_SBI_1_0_ProviderImpl.rCapture}). [CODE]: shape mirror, not the client itself.
 */
class StockClientParseCompatibilityTest {
    public static class RcError { public String errorCode, errorInfo; }
    public static class RcBiometrics { public String specVersion, data, hash; public RcError error; public HashMap<String, String> additionalInfo; }
    public static class RcResponse { public List<RcBiometrics> biometrics; }

    @BeforeAll
    static void keys() throws Exception {
        CaptureBinderTest.keys();
    }

    @Test
    void draftCarrierInAdditionalInfoParsesWithTheStockClientMapper() throws Exception {
        B1Fixture fx = new B1Fixture("txn-1");
        fx.emit(B1Fixture.frameBytes(0), System.currentTimeMillis());
        byte[] resp = fx.attach(CaptureBinderTest.response(c -> c.txn = "txn-1"));
        RcResponse r = new ObjectMapper().readValue(resp, RcResponse.class);
        assertEquals(1, r.biometrics.size());
        assertEquals(3, r.biometrics.get(0).additionalInfo.get("streamDigest").split("\\.").length);
    }

    @Test
    void prototypeV0TopLevelCarrierWouldBreakTheStockClient() throws Exception {
        B1Fixture fx = new B1Fixture("txn-1");
        fx.topLevelCarrier = true;
        byte[] resp = fx.attach(CaptureBinderTest.response(c -> c.txn = "txn-1"));
        assertThrows(UnrecognizedPropertyException.class, () -> new ObjectMapper().readValue(resp, RcResponse.class));
    }
}
