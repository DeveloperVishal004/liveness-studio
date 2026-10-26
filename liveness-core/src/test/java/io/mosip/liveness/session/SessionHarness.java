package io.mosip.liveness.session;

import io.mosip.liveness.binding.BindingResult;
import io.mosip.liveness.binding.CaptureBinder;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Drives a {@link LivenessSession} with synthetic per-frame evidence on a fake clock. The evidence is [SIM]: grey crops are
 * random textures (varying) or one fixed texture (static), not faces. It exercises decision logic only — never vision.
 */
public final class SessionHarness {

    /** Monotonic and wall clocks under test control. The wall clock can be made to jump independently. */
    public static final class FakeClock implements SessionClock {
        public volatile long mono = 5_000_000_000L;      // volatile: read by verification threads in concurrency tests
        public volatile long wall = System.currentTimeMillis();

        @Override
        public long monoNanos() { return mono; }

        @Override
        public long wallMillis() { return wall; }

        public void advance(long ms) {
            mono += ms * 1_000_000L;
            wall += ms;
        }
    }

    public enum Kind { LIVE, STATIC, FROZEN, MULTI, NO_FACE }

    /** Verifier double: returns {@link #next} (or throws {@link #toThrow}) and records every context it saw. */
    public static final class StubVerifier implements CaptureVerifier {
        public BindingResult next;
        public RuntimeException toThrow;
        public final List<CaptureBinder.SessionContext> seen = new ArrayList<>();
        public final List<java.time.Instant> nows = new ArrayList<>();

        @Override
        public BindingResult bind(byte[] response, CaptureBinder.SessionContext ctx, java.time.Instant now) {
            seen.add(ctx);
            nows.add(now);
            if (toThrow != null) {
                throw toThrow;
            }
            return next;
        }
    }

    public static final float[] SUBJECT = unit(0);
    public static final float[] OTHER = unit(1);
    public static final String HASH = "ab".repeat(32);
    static final float[][] LM = {{20, 24}, {44, 24}, {32, 36}, {24, 48}, {40, 48}};

    public final FakeClock clock = new FakeClock();
    public final SessionPolicy policy;
    public final AttemptLedger ledger;
    public final LivenessSession session;
    public long frameIntervalMs = 67;           // ~15 fps
    public float pad = 0.95f;
    public float yaw = 0f;
    public float[] embedding = SUBJECT;
    public boolean embed = true;
    long seq;
    private final Random rng = new Random(7);
    private final float[] staticGrey = texture(new Random(99));
    public final List<FrameTag> tags = new ArrayList<>();
    public volatile String lastTxn;

    public SessionHarness(SessionPolicy policy, AttemptLedger ledger, CaptureVerifier verifier, String certification) {
        this(policy, ledger, verifier, certification, null);
    }

    public SessionHarness(SessionPolicy policy, AttemptLedger ledger, CaptureVerifier verifier, String certification,
                          io.mosip.liveness.streamauth.StreamAuthenticator streamAuth) {
        this.policy = policy;
        this.ledger = ledger;
        this.session = new LivenessSession(policy, clock, verifier, ledger, "subject-1",
                new LivenessSession.DeviceIdentity("PHASE0-MOCK-FACE-0001", "Phase0", "MOCK-FACE-1", certification), streamAuth);
        this.b1 = streamAuth != null;
    }

    // ---- B1 mode: the "device" emits frame bytes; an attacker on the wire may replace (return other bytes) or drop
    //      (return null) them; the client hashes what it receives at the receipt boundary.
    public boolean b1;
    public final List<byte[]> sentFrames = new ArrayList<>();
    public final List<Long> sentTimes = new ArrayList<>();
    public java.util.function.UnaryOperator<byte[]> wire = java.util.function.UnaryOperator.identity();
    private final String frameSalt = Long.toHexString(new Random().nextLong());

    public static float[] unit(int axis) {
        float[] v = new float[128];
        v[axis] = 1f;
        return v;
    }

    static float[] texture(Random r) {
        float[] g = new float[64 * 64];
        for (int i = 0; i < g.length; i++) {
            g[i] = (float) r.nextGaussian();
        }
        return g;
    }

    /** Advances the clock by one frame interval and delivers {@code n} frames of the given kind. */
    public void frames(int n, Kind k) {
        for (int i = 0; i < n; i++) {
            clock.advance(frameIntervalMs);
            seq++;
            FrameTag t;
            if (b1) {
                byte[] emitted = (frameSalt + "-frame-" + sentFrames.size()).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                sentFrames.add(emitted);
                sentTimes.add(clock.wall);
                byte[] onWire = wire.apply(emitted);
                if (onWire == null) {
                    continue;                          // dropped on the wire: never received
                }
                t = session.tagArrival(onWire);        // hashed at receipt
            } else {
                t = session.tagArrival();              // trusted boundary: session clock + session sequence
            }
            tags.add(t);
            deliver(t, k);
        }
    }

    public void deliver(FrameTag t, Kind k) {
        switch (k) {
            case LIVE:
                session.onEvidence(t, 1, true, null, pad, LM, new float[] {10, 10, 44, 54}, texture(rng), yaw);
                break;
            case STATIC:
                session.onEvidence(t, 1, true, null, pad, LM, new float[] {10, 10, 44, 54}, staticGrey.clone(), yaw);
                break;
            case FROZEN:
                session.onEvidence(t, -1, false, "FROZEN_FRAME", null, null, null, null, Float.NaN);
                return;
            case MULTI:
                session.onEvidence(t, 2, false, "MULTIPLE_FACES", null, null, null, null, Float.NaN);
                return;
            case NO_FACE:
            default:
                session.onEvidence(t, 0, false, "NO_FACE", null, null, null, null, Float.NaN);
                return;
        }
        if (embed) {
            session.onEmbedding(t, embedding);
        }
    }

    /** Collects live evidence until READY_FOR_CAPTURE (or gives up after 5 s of frames). */
    public SessionOutcome.State untilReady() {
        for (int i = 0; i < 75 && session.state() == SessionOutcome.State.CAPTURING; i++) {
            frames(1, Kind.LIVE);
        }
        return session.state();
    }
}
