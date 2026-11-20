package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class CachedFlagTest {

    final AtomicBoolean source = new AtomicBoolean(true);
    final AtomicInteger reads = new AtomicInteger();
    final AtomicLong nanos = new AtomicLong(1_000);
    final CachedFlag flag = new CachedFlag(() -> {
        reads.incrementAndGet();
        return source.get();
    }, Duration.ofSeconds(1), nanos::get);

    @Test
    void readsTheSourceOncePerPeriod() {
        assertTrue(flag.get());
        source.set(false);
        assertTrue(flag.get());
        assertEquals(1, reads.get());
        nanos.addAndGet(Duration.ofSeconds(1).toNanos());
        assertFalse(flag.get());
        assertEquals(2, reads.get());
    }
}
