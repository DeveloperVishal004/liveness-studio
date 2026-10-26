package io.mosip.liveness.session;

/**
 * Time source for a session.
 *
 * <p><b>Clock model.</b> {@link #monoNanos()} (monotonic) is the only time used for ordering, freshness, timeouts and
 * capture windows. {@link #wallMillis()} (wall clock, can jump) is used only to map device-signed timestamps and for
 * audit. A session records the offset {@code wall - mono} when each attempt starts; if the offset moves by more than
 * {@link SessionPolicy#clockJumpToleranceMs} before a capture is bound, the attempt fails closed with
 * {@code CLOCK_DISCONTINUITY} and a retry re-baselines.
 *
 * <p><b>Process restarts.</b> Monotonic values are meaningless across processes, so sessions live in memory only and are
 * never resumed after a restart; the caller starts a new session. Retry/attack limits survive a restart only if the
 * {@link AttemptLedger} is persistent (the in-memory ledger is not; see its documentation).
 */
public interface SessionClock {
    long monoNanos();

    long wallMillis();

    SessionClock SYSTEM = new SessionClock() {
        @Override
        public long monoNanos() { return System.nanoTime(); }

        @Override
        public long wallMillis() { return System.currentTimeMillis(); }
    };
}
