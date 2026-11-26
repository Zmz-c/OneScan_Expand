package burp.vaycore.common.helper;

import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Shared request pacing. No lock is held while waiting or performing network I/O.
 */
public class QpsLimiter {

    private static final long PERIOD = TimeUnit.SECONDS.toNanos(1);
    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition changed = lock.newCondition();
    private long[] accessTime;
    private int position;
    private int count;
    private int delay;
    private boolean randomEnabled;
    private int randomMin;
    private int randomMax;
    private boolean pacedDeadlineSet;
    private long pacedDeadline;

    public QpsLimiter(int limit) {
        this(limit, 0);
    }

    public QpsLimiter(int limit, int delay) {
        configure(limit, delay, false, 0, 0);
    }

    /**
     * Updates the existing gate and wakes its waiters, including on disable.
     */
    public void configure(int limit, int delay, boolean randomEnabled, int randomMin, int randomMax) {
        if (limit <= 0) {
            throw new IllegalArgumentException("Illegal limit value: " + limit);
        }
        if (randomMin < 0 || randomMax < randomMin) {
            throw new IllegalArgumentException("Illegal random delay range");
        }
        lock.lock();
        try {
            this.accessTime = new long[limit];
            this.position = 0;
            this.count = 0;
            this.delay = Math.max(0, delay);
            this.randomEnabled = randomEnabled;
            this.randomMin = randomMin;
            this.randomMax = randomMax;
            this.pacedDeadlineSet = false;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public void limit() throws InterruptedException {
        limit(true);
    }

    /**
     * Random pacing covers every caller, even lanes that bypass legacy limits.
     * Fixed delay retains its original precedence over QPS. With random pacing,
     * fixed delay is replaced and the regular HTTP lane still observes QPS.
     */
    public void limit(boolean applyLegacyLimit) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (true) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Request pacing interrupted");
                }
                long now = System.nanoTime();
                boolean paced = randomEnabled || (applyLegacyLimit && delay > 0);
                boolean useQps = applyLegacyLimit && (randomEnabled || delay == 0);
                long wait = 0;
                if (paced) {
                    if (!pacedDeadlineSet) {
                        pacedDeadline = now + nextDelayNanos();
                        pacedDeadlineSet = true;
                    }
                    wait = Math.max(0, pacedDeadline - now);
                }
                if (useQps && count == accessTime.length) {
                    wait = Math.max(wait, PERIOD - (now - accessTime[position]));
                }
                if (wait > 0) {
                    changed.awaitNanos(wait);
                    continue;
                }
                if (useQps) {
                    accessTime[position] = now;
                    position = (position + 1) % accessTime.length;
                    count = Math.min(count + 1, accessTime.length);
                }
                if (paced) {
                    pacedDeadline = now + nextDelayNanos();
                }
                return;
            }
        } finally {
            lock.unlock();
        }
    }

    private long nextDelayNanos() {
        long millis = randomEnabled
                ? ThreadLocalRandom.current().nextLong(randomMin, (long) randomMax + 1)
                : delay;
        return TimeUnit.MILLISECONDS.toNanos(millis);
    }
}
