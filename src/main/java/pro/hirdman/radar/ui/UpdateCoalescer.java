package pro.hirdman.radar.ui;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

/** Folds bursts of changes into one flush per timer tick: {@code mark()} from any thread, {@code tick()} on the timer. */
public final class UpdateCoalescer {

    private final Duration period;
    private final Runnable flush;
    private final AtomicBoolean dirty = new AtomicBoolean();

    public UpdateCoalescer(Duration period, Runnable flush) {
        this.period = period;
        this.flush = flush;
    }

    public void mark() {
        dirty.set(true);
    }

    public void tick() {
        if (dirty.getAndSet(false)) {
            flush.run();
        }
    }

    public int periodMillis() {
        return (int) period.toMillis();
    }
}
