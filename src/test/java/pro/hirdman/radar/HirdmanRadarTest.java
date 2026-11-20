package pro.hirdman.radar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

class HirdmanRadarTest {

    @Test
    void theExtensionNameSaysWhatItDoes() {
        assertEquals("Hirdman Radar: Subdomain Leak Check", HirdmanRadar.NAME);
    }

    @Test
    void everyUnloadStepRunsWhenOneFails() {
        List<String> ran = new CopyOnWriteArrayList<>();
        List<String> errors = new CopyOnWriteArrayList<>();
        HirdmanRadar.runAll(errors::add, () -> ran.add("traffic"), () -> {
            throw new IllegalStateException("tab broke");
        }, () -> ran.add("queue"), () -> ran.add("save"));
        assertEquals(List.of("traffic", "queue", "save"), ran);
        assertEquals(1, errors.size(), errors.toString());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: unload step failed: "), errors.get(0));
        assertTrue(errors.get(0).contains("tab broke"), errors.get(0));
    }

    @Test
    void unloadStepsShareOneBudget() {
        long now = System.nanoTime();
        assertEquals(Duration.ofSeconds(2), HirdmanRadar.left(now + Duration.ofSeconds(10).toNanos(), Duration.ofSeconds(2)));
        assertEquals(Duration.ZERO, HirdmanRadar.left(now - 1, Duration.ofSeconds(2)));
        assertTrue(HirdmanRadar.left(now + Duration.ofSeconds(1).toNanos(), Duration.ofSeconds(2)).compareTo(Duration.ofSeconds(1)) <= 0);
    }
}
