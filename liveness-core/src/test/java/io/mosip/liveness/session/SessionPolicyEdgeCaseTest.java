package io.mosip.liveness.session;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A session refuses to be created with a nonsensical or overflow-prone policy (fail closed at configuration time). [CODE] */
class SessionPolicyEdgeCaseTest {
    private static void rejected(String what, Consumer<SessionPolicy> edit) {
        SessionPolicy p = new SessionPolicy();
        edit.accept(p);
        assertThrows(IllegalArgumentException.class, p::validate, what);
    }

    @Test
    void defaultsAreValid() {
        assertDoesNotThrow(() -> new SessionPolicy().validate());
        assertDoesNotThrow(() -> new SessionPolicy().copy().validate());
    }

    @Test
    void thresholdsMustBeFiniteProbabilitiesWithAttackBelowAccept() {
        rejected("NaN accept", p -> p.streamAccept = Float.NaN);
        rejected("NaN attack", p -> p.streamAttack = Float.NaN);
        rejected("accept > 1", p -> p.streamAccept = 1.0001f);
        rejected("accept inf", p -> p.streamAccept = Float.POSITIVE_INFINITY);
        rejected("attack < 0", p -> p.streamAttack = -0.0001f);
        rejected("attack == accept", p -> { p.streamAttack = 0.8f; p.streamAccept = 0.8f; });
        rejected("attack > accept", p -> { p.streamAttack = 0.9f; p.streamAccept = 0.8f; });
        assertDoesNotThrow(() -> { SessionPolicy p = new SessionPolicy(); p.streamAttack = 0f; p.streamAccept = 1f; p.validate(); });
    }

    @Test
    void zeroNegativeAndNanLimitsAreRejected() {
        rejected("0 attempts", p -> p.maxAttempts = 0);
        rejected("negative attack events", p -> p.maxAttackEvents = -1);
        rejected("negative channel events", p -> p.maxChannelEvents = -1);
        rejected("zero collect timeout", p -> p.collectTimeoutMs = 0);
        rejected("negative ttl", p -> p.sessionTtlMs = -5);
        rejected("zero passive window", p -> p.passiveWindowMs = 0);
        rejected("1 passive frame", p -> p.passiveMinFrames = 1);
        rejected("0 attack frames", p -> p.attackMinFrames = 0);
        rejected("NaN static threshold", p -> p.staticPhotoThreshold = Double.NaN);
        rejected("zero static threshold", p -> p.staticPhotoThreshold = 0);
        rejected("NaN cosine", p -> p.subjectMinCosine = Float.NaN);
        rejected("zero cosine", p -> p.subjectMinCosine = 0f);
        rejected("cosine > 1", p -> p.subjectMinCosine = 1.01f);
        rejected("NaN yaw", p -> p.frontalMaxAbsYaw = Float.NaN);
        rejected("zero window gap", p -> p.windowMaxGapMs = 0);
        rejected("0 embeddings required", p -> p.windowMinEmbeddings = 0);
    }

    @Test
    void certificationMustBeExactlyNullL0OrL1() {
        for (String bad : new String[] {"", "l1", "L2", " L1", "L1 ", "L0\n", "null"}) {
            rejected("certification '" + bad + "'", p -> p.requiredCertification = bad);
        }
        for (String ok : new String[] {null, "L0", "L1"}) {
            assertDoesNotThrow(() -> { SessionPolicy p = new SessionPolicy(); p.requiredCertification = ok; p.validate(); });
        }
    }

    @Test
    void recordsMustOutliveTheWindowsThatNeedThem() {
        rejected("records evicted before the passive window ends", p -> p.maxRecordAgeMs = p.passiveWindowMs);
        rejected("records evicted before the static window ends", p -> p.maxRecordAgeMs = p.staticWindowMs);
        rejected("records evicted before a capture can finish", p -> p.maxRecordAgeMs = p.captureTimeoutMs + p.windowLatencyMs);
        rejected("store smaller than the passive evidence", p -> p.maxRecords = 2 * p.passiveMinFrames - 1);
    }

    /**
     * The session multiplies millisecond limits by 1,000,000 to get nanoseconds. A value near Long.MAX_VALUE would
     * overflow and silently turn a window negative, so validation must bound every such field.
     */
    @Test
    void millisecondLimitsThatWouldOverflowNanosecondArithmeticAreRejected() throws Exception {
        String[] msFields = {"collectTimeoutMs", "readyTimeoutMs", "captureTimeoutMs", "sessionTtlMs", "passiveWindowMs",
                "passiveMinSpanMs", "staticWindowMs", "windowLatencyMs", "windowMaxGapMs", "clockJumpToleranceMs",
                "maxArrivalAgeMs", "maxRecordAgeMs"};
        for (String name : msFields) {
            Field f = SessionPolicy.class.getField(name);
            for (long absurd : new long[] {Long.MAX_VALUE, Long.MAX_VALUE / 1_000_000L + 1, 10_000_000_000_000L}) {
                SessionPolicy p = new SessionPolicy();
                f.setLong(p, absurd);
                if (name.equals("maxRecordAgeMs")) {
                    // keep the other relations satisfied so only the magnitude is under test
                    p.sessionTtlMs = Math.min(p.sessionTtlMs, 120_000);
                }
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, p::validate, name + "=" + absurd);
                assertTrue(e.getMessage().startsWith("invalid SessionPolicy"), e.getMessage());
            }
        }
        // and the upper bound is generous: a full day is still accepted for every field
        for (String name : msFields) {
            SessionPolicy p = new SessionPolicy();
            SessionPolicy.class.getField(name).setLong(p, 86_400_000L);
            p.maxRecordAgeMs = 172_800_000L;                       // the 48 h cap: records outlive any 24 h window
            if (name.equals("maxRecordAgeMs")) {
                p.maxRecordAgeMs = 86_400_000L;
            }
            final SessionPolicy q = p;
            assertDoesNotThrow(q::validate, name + " = 24 h");
        }
    }

    @Test
    void copyIsDeepAndLaterMutationHasNoEffect() {
        SessionPolicy p = new SessionPolicy();
        p.streamAccept = 0.9f;
        SessionPolicy c = p.copy();
        p.streamAccept = 0.1f;
        p.maxAttempts = 99;
        assertEquals(0.9f, c.streamAccept, 0f);
        assertEquals(3, c.maxAttempts);
    }
}
