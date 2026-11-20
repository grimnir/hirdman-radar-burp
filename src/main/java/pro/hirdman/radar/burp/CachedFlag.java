package pro.hirdman.radar.burp;

import java.time.Duration;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/** A setting read on every message: asks Burp at most once per period and answers from a volatile copy in between. */
final class CachedFlag {

    private final BooleanSupplier source;
    private final long periodNanos;
    private final LongSupplier nanoTime;
    private volatile boolean value;
    private volatile long readAt;
    private volatile boolean read;

    CachedFlag(BooleanSupplier source, Duration period) {
        this(source, period, System::nanoTime);
    }

    CachedFlag(BooleanSupplier source, Duration period, LongSupplier nanoTime) {
        this.source = source;
        this.periodNanos = period.toNanos();
        this.nanoTime = nanoTime;
    }

    boolean get() {
        long now = nanoTime.getAsLong();
        if (!read || now - readAt >= periodNanos) {
            // Two threads may both refresh at once; either answer is current.
            value = source.getAsBoolean();
            readAt = now;
            read = true;
        }
        return value;
    }
}
