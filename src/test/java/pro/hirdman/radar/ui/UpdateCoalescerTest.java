package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class UpdateCoalescerTest {

    final AtomicInteger flushes = new AtomicInteger();
    final UpdateCoalescer c = new UpdateCoalescer(Duration.ofMillis(250), flushes::incrementAndGet);

    @Test
    void coalescerFlushesOncePerPeriod() {
        for (int i = 0; i < 100; i++) {
            c.mark();
        }
        c.tick();
        assertEquals(1, flushes.get());
        c.tick();
        assertEquals(1, flushes.get());
        c.mark();
        c.tick();
        assertEquals(2, flushes.get());
    }

    @Test
    void marksFromOtherThreadsCount() throws InterruptedException {
        Thread t = new Thread(c::mark);
        t.start();
        t.join();
        c.tick();
        assertEquals(1, flushes.get());
    }

    @Test
    void periodIsTheTimerDelay() {
        assertEquals(250, c.periodMillis());
    }
}
