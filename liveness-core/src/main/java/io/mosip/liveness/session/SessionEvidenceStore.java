package io.mosip.liveness.session;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Bounded, time-ordered store of accepted evidence for ONE session. Not thread-safe on its own: owned and guarded by
 * {@link LivenessSession}. Records are appended only after the {@code EvidenceGate} accepted them, so they are in
 * strictly increasing {@code seq} (and arrival time) order within an epoch.
 */
final class SessionEvidenceStore {
    private final Deque<EvidenceRecord> records = new ArrayDeque<>();
    private final int maxRecords;
    private final long maxAgeNanos;

    SessionEvidenceStore(int maxRecords, long maxAgeNanos) {
        this.maxRecords = maxRecords;
        this.maxAgeNanos = maxAgeNanos;
    }

    void append(EvidenceRecord r, long nowNanos) {
        records.addLast(r);
        while (records.size() > maxRecords) {
            records.removeFirst();
        }
        while (!records.isEmpty() && nowNanos - records.peekFirst().monoNanos > maxAgeNanos) {
            records.removeFirst();
        }
    }

    /** Record for a given epoch and seq, or null (e.g. evicted). */
    EvidenceRecord find(long epoch, long seq) {
        for (EvidenceRecord r : records) {
            if (r.epoch == epoch && r.seq == seq) {
                return r;
            }
        }
        return null;
    }

    /** Records of {@code epoch} whose arrival time is in {@code [fromNanos, toNanos]} (overflow-safe), oldest first. */
    List<EvidenceRecord> window(long epoch, long fromNanos, long toNanos) {
        List<EvidenceRecord> out = new ArrayList<>();
        for (EvidenceRecord r : records) {
            if (r.epoch == epoch && r.monoNanos - fromNanos >= 0 && toNanos - r.monoNanos >= 0) {
                out.add(r);
            }
        }
        return out;
    }

    /** All records of {@code epoch}, oldest first. */
    List<EvidenceRecord> epoch(long epoch) {
        List<EvidenceRecord> out = new ArrayList<>();
        for (EvidenceRecord r : records) {
            if (r.epoch == epoch) {
                out.add(r);
            }
        }
        return out;
    }

    /** Drops everything (retry, cancel, shutdown): positive evidence never carries over. */
    void clear() {
        records.clear();
    }

    int size() { return records.size(); }
}
