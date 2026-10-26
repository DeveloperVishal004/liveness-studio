package io.mosip.liveness.streamauth;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Verifies that the stream frames a session used are covered by device-signed evidence. May throw (fails closed). */
public interface StreamAuthenticator {

    /** One received frame of the attempt, in receipt order. */
    final class FrameRef {
        public final long tagSeq;
        /** SHA-256 of the received JPEG bytes, computed at receipt; null if the frame was tagged without bytes. */
        public final byte[] sha256;
        /** Accepted by the frame gate as evidence for this attempt. */
        public final boolean evidence;
        /** Arrived inside the capture window [t_req - δ_lat, t_resp]. */
        public final boolean inCaptureWindow;

        public FrameRef(long tagSeq, byte[] sha256, boolean evidence, boolean inCaptureWindow) {
            this.tagSeq = tagSeq;
            this.sha256 = sha256;
            this.evidence = evidence;
            this.inCaptureWindow = inCaptureWindow;
        }
    }

    final class Context {
        public final String transactionId;
        public final String deviceSerial;
        public final Instant windowFrom;
        public final Instant windowTo;
        public final List<FrameRef> received;
        public final int maxUncoveredTail;
        public final int maxMissingInWindow;
        public final long statementSkewMs;

        public Context(String transactionId, String deviceSerial, Instant windowFrom, Instant windowTo,
                       List<FrameRef> received, int maxUncoveredTail, int maxMissingInWindow, long statementSkewMs) {
            this.transactionId = Objects.requireNonNull(transactionId);
            this.deviceSerial = Objects.requireNonNull(deviceSerial);
            this.windowFrom = Objects.requireNonNull(windowFrom);
            this.windowTo = Objects.requireNonNull(windowTo);
            this.received = Collections.unmodifiableList(new ArrayList<>(received));
            this.maxUncoveredTail = maxUncoveredTail;
            this.maxMissingInWindow = maxMissingInWindow;
            this.statementSkewMs = statementSkewMs;
        }
    }

    StreamAuthResult verify(byte[] rcaptureResponse, Context ctx, Instant now);
}
