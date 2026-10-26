package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.CaptureBinder;

import java.time.Instant;

/** The session's view of capture binding ({@link CaptureBinder} in production). May throw; the session fails closed. */
public interface CaptureVerifier {
    BindingResult bind(byte[] rcaptureResponse, CaptureBinder.SessionContext ctx, Instant now);
}
