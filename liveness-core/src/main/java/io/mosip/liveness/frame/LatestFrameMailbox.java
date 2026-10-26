package io.mosip.liveness.frame;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Single-slot, overwrite-on-write hand-off between the stream reader and the inference worker.
 *
 * <p>If the worker is slower than the device, older frames are replaced (and counted) instead of queueing,
 * so per-frame latency cannot grow without bound. Security evidence requirements are expressed in both
 * frames <em>and</em> seconds elsewhere, so dropping frames here can only slow a decision down, never
 * weaken it.
 */
public final class LatestFrameMailbox<T> {
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition available = lock.newCondition();
    private T slot;
    private boolean closed;
    private final AtomicLong offered = new AtomicLong();
    private final AtomicLong overwritten = new AtomicLong();

    /** Publishes {@code item}; returns {@code true} if an untaken item was overwritten. */
    public boolean offer(T item) {
        lock.lock();
        try {
            if (closed) {
                return false;
            }
            offered.incrementAndGet();
            boolean replaced = slot != null;
            if (replaced) {
                overwritten.incrementAndGet();
            }
            slot = item;
            available.signal();
            return replaced;
        } finally {
            lock.unlock();
        }
    }

    /** Takes the newest item, waiting up to {@code timeout}; returns {@code null} on timeout or close. */
    public T take(long timeout, TimeUnit unit) throws InterruptedException {
        long nanos = unit.toNanos(timeout);
        lock.lock();
        try {
            while (slot == null && !closed) {
                if (nanos <= 0L) {
                    return null;
                }
                nanos = available.awaitNanos(nanos);
            }
            T item = slot;
            slot = null;
            return item;
        } finally {
            lock.unlock();
        }
    }

    public void close() {
        lock.lock();
        try {
            closed = true;
            slot = null;
            available.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public long offeredCount() { return offered.get(); }
    public long overwrittenCount() { return overwritten.get(); }
}
