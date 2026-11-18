package pro.hirdman.radar.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class NewHostBatcherTest {

    static final Instant T0 = Instant.parse("2026-11-17T12:00:00Z");

    final Map<String, Instant> checked = new HashMap<>();
    final AtomicReference<String> server = new AtomicReference<>("scan.hirdman.pro");
    final NewHostBatcher b = new NewHostBatcher(Duration.ofSeconds(60), Duration.ofHours(24),
            h -> Optional.ofNullable(checked.get(h)), server::get);

    @Test
    void drainsAtMostOncePerMinute() {
        b.offer("a.example.com", true);
        assertEquals(List.of("a.example.com"), b.drain(T0));
        b.offer("b.example.com", true);
        assertEquals(List.of(), b.drain(T0.plusSeconds(30)));
        assertEquals(List.of("b.example.com"), b.drain(T0.plusSeconds(60)));
        assertEquals(List.of(), b.drain(T0.plusSeconds(200)));
    }

    @Test
    void skipsOutOfScopeAndIps() {
        b.offer("out.example.com", false);
        b.offer("10.0.0.1", true);
        b.offer("::1", true);
        b.offer("[::1]", true);
        b.offer("_dmarc.example.com", true);
        b.offer(null, true);
        b.offer("in.example.com", true);
        assertEquals(List.of("in.example.com"), b.drain(T0));
    }

    @Test
    void skipsTheRadarServer() {
        b.offer("scan.hirdman.pro", true);
        b.offer("SCAN.hirdman.pro.", true);
        assertEquals(List.of(), b.drain(T0));
        server.set("radar.local.test");
        b.offer("scan.hirdman.pro", true);
        b.offer("radar.local.test", true);
        assertEquals(List.of("scan.hirdman.pro"), b.drain(T0.plusSeconds(60)));
    }

    @Test
    void skipsHostsCheckedWithinDay() {
        checked.put("recent.example.com", T0.minus(Duration.ofHours(23)));
        checked.put("old.example.com", T0.minus(Duration.ofHours(25)));
        b.offer("recent.example.com", true);
        b.offer("old.example.com", true);
        assertEquals(List.of("old.example.com"), b.drain(T0));
    }

    @Test
    void deduplicates() {
        b.offer("a.example.com", true);
        b.offer("A.EXAMPLE.COM", true);
        b.offer("a.example.com.", true);
        b.offer("b.example.com", true);
        assertEquals(List.of("a.example.com", "b.example.com"), b.drain(T0));
    }

    @Test
    void drainedHostsWaitOutTheWindowToo() {
        b.offer("a.example.com", true);
        assertEquals(List.of("a.example.com"), b.drain(T0));
        b.offer("a.example.com", true);
        assertEquals(List.of(), b.drain(T0.plus(Duration.ofHours(23))));
        b.offer("a.example.com", true);
        assertEquals(List.of("a.example.com"), b.drain(T0.plus(Duration.ofHours(25))));
    }

    @Test
    void serverHostIsComparedAsAName() {
        server.set("SCAN.Hirdman.PRO.");
        b.offer("scan.hirdman.pro", true);
        assertEquals(List.of(), b.drain(T0));
    }

    @Test
    void aBatchIsHandedOutOnce() {
        b.offer("a.example.com", true);
        assertEquals(List.of("a.example.com"), b.drain(T0));
        assertEquals(List.of(), b.drain(T0.plus(Duration.ofHours(25))));
    }

    @Test
    void serverHostIsReadOncePerDrain() {
        java.util.concurrent.atomic.AtomicInteger reads = new java.util.concurrent.atomic.AtomicInteger();
        NewHostBatcher counted = new NewHostBatcher(Duration.ofSeconds(60), Duration.ofHours(24), h -> Optional.empty(), () -> {
            reads.incrementAndGet();
            return "scan.hirdman.pro";
        });
        for (int i = 0; i < 50; i++) {
            counted.offer("h" + i + ".example.com", true);
        }
        assertEquals(0, reads.get());
        assertEquals(50, counted.drain(T0).size());
        assertEquals(1, reads.get());
    }

    @Test
    void pendingIsCapped() {
        for (int i = 0; i < NewHostBatcher.MAX_PENDING + 10; i++) {
            b.offer("h" + i + ".example.com", true);
        }
        assertEquals(NewHostBatcher.MAX_PENDING, b.drain(T0).size());
    }

    @Test
    void clearDropsWhatIsPending() {
        b.offer("a.example.com", true);
        b.clear();
        assertTrue(b.drain(T0).isEmpty());
    }

    @Test
    void trafficIsNotHeldUpWhileADrainLooksUpHosts() {
        // offer runs on Burp's HTTP threads; the store lookups of a drain must not make them wait.
        ExecutorService traffic = Executors.newSingleThreadExecutor();
        AtomicReference<NewHostBatcher> self = new AtomicReference<>();
        NewHostBatcher slow = new NewHostBatcher(Duration.ofSeconds(60), Duration.ofHours(24), h -> {
            try {
                traffic.submit(() -> self.get().offer("late.example.com", true)).get(2, TimeUnit.SECONDS);
            } catch (Exception e) {
                throw new AssertionError("offer waited for the drain", e);
            }
            return Optional.empty();
        }, server::get);
        self.set(slow);
        try {
            slow.offer("a.example.com", true);
            assertEquals(List.of("a.example.com"), slow.drain(T0));
            assertEquals(List.of("late.example.com"), slow.drain(T0.plusSeconds(60)));
        } finally {
            traffic.shutdownNow();
        }
    }
}
