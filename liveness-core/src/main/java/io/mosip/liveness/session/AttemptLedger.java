package io.mosip.liveness.session;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Retry and attack-event counters keyed by the workflow's subject context (registration id, operator id, ...), plus
 * channel-integrity counters keyed by the capture channel (device), all kept <b>outside</b> any one session so a new
 * session cannot reset them.
 *
 * <p><b>Attribution (owner decision 2026-10-24):</b> attack events count against the <em>subject</em> only when the
 * subject plausibly caused them (presentation/evidence attacks). Events that cannot be attributed to the subject
 * (unauthenticated or unbound responses) count against the <em>channel</em>. Neither path accepts the response.
 *
 * <p><b>Recovery:</b> counters never decrease automatically. The only recovery path is the explicit, audited
 * {@link #resetChannel administrative channel reset}. Counters saturate at {@link Integer#MAX_VALUE} (never wrap).
 *
 * <p><b>Production requirement (open):</b> the ledger must be persistent and tamper-evident (for example in the
 * Registration Client's encrypted Derby database); {@link FileAttemptLedger} is the reference implementation. With
 * {@link InMemory}, restarting the process resets the limits — acceptable for tests and the Phase-0 tools only.
 */
public interface AttemptLedger {
    int attempts(String key);

    int attackEvents(String key);

    /** Records a new attempt and returns the updated count. */
    int recordAttempt(String key);

    /** Records an attack event attributable to the subject and returns the updated count. */
    int recordAttackEvent(String key);

    /** Device faults recorded for diagnosis (never a lockout input). Ledgers without support report 0. */
    default int deviceFaults(String key) { return 0; }

    /** Records a device fault for diagnosis and returns the updated count (0 if unsupported). */
    default int recordDeviceFault(String key) { return 0; }

    /** Channel-integrity events recorded for {@code channelKey} since its last administrative reset. */
    int channelEvents(String channelKey);

    /** Records a channel-integrity event with a diagnostic reason; returns the updated count. */
    int recordChannelEvent(String channelKey, String reason);

    /** Diagnostic: the reason of the most recent channel-integrity event, or null. */
    String lastChannelReason(String channelKey);

    /**
     * ADMINISTRATIVE reset of a channel's integrity counter, after a person has investigated the channel. Never called
     * by the engine. {@code authorizedBy} and {@code justification} are mandatory and recorded in the reset audit.
     */
    void resetChannel(String channelKey, String authorizedBy, String justification);

    /** Audit entries of administrative resets (oldest first). */
    List<String> resetAudit();

    /** False if the stored counters could not be authenticated (tampered or unreadable): sessions must not start. */
    default boolean trustworthy() { return true; }

    /** Saturating increment: a counter never wraps to a negative value. */
    static int inc(int v) {
        return v == Integer.MAX_VALUE ? v : v + 1;
    }

    static void requireResetAuthorization(String authorizedBy, String justification) {
        if (authorizedBy == null || authorizedBy.trim().isEmpty() || justification == null || justification.trim().isEmpty()) {
            throw new IllegalArgumentException("an administrative reset needs authorizedBy and justification");
        }
    }

    /** In-memory ledger. NOT persistent: a process restart resets every counter. */
    final class InMemory implements AttemptLedger {
        private final ConcurrentHashMap<String, int[]> counts = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, Integer> channels = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, String> channelReasons = new ConcurrentHashMap<>();
        private final List<String> audit = new ArrayList<>();

        private int[] c(String key) {
            return counts.computeIfAbsent(key, k -> new int[3]);
        }

        @Override
        public synchronized int attempts(String key) { return c(key)[0]; }

        @Override
        public synchronized int attackEvents(String key) { return c(key)[1]; }

        @Override
        public synchronized int recordAttempt(String key) { return c(key)[0] = inc(c(key)[0]); }

        @Override
        public synchronized int recordAttackEvent(String key) { return c(key)[1] = inc(c(key)[1]); }

        @Override
        public synchronized int deviceFaults(String key) { return c(key)[2]; }

        @Override
        public synchronized int recordDeviceFault(String key) { return c(key)[2] = inc(c(key)[2]); }

        @Override
        public synchronized int channelEvents(String channelKey) { return channels.getOrDefault(channelKey, 0); }

        @Override
        public synchronized int recordChannelEvent(String channelKey, String reason) {
            int n = inc(channels.getOrDefault(channelKey, 0));
            channels.put(channelKey, n);
            channelReasons.put(channelKey, String.valueOf(reason));
            return n;
        }

        @Override
        public synchronized String lastChannelReason(String channelKey) { return channelReasons.get(channelKey); }

        @Override
        public synchronized void resetChannel(String channelKey, String authorizedBy, String justification) {
            requireResetAuthorization(authorizedBy, justification);
            audit.add("reset channel=" + channelKey + " previous=" + channelEvents(channelKey) + " by=" + authorizedBy
                    + " why=" + justification + " at=" + System.currentTimeMillis());
            channels.remove(channelKey);
            channelReasons.remove(channelKey);
        }

        @Override
        public synchronized List<String> resetAudit() { return Collections.unmodifiableList(new ArrayList<>(audit)); }
    }
}
