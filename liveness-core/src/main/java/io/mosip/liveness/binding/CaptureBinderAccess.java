package io.mosip.liveness.binding;

import java.time.Instant;

/** Exposes the binder's tolerant SBI timestamp parser to diagnostic tools (same parsing as binding decisions). */
public final class CaptureBinderAccess {
    private CaptureBinderAccess() {}

    /** Returns null if unparseable. */
    public static Instant parseTimestamp(String s) {
        return CaptureBinder.parseTimestamp(s);
    }
}
