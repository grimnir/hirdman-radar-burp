package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(10)
class BurpThreadTest {

    final List<String> errors = new CopyOnWriteArrayList<>();
    final List<String> ran = new CopyOnWriteArrayList<>();

    @Test
    void runsTasksInOrderOffTheCallersThread() throws Exception {
        BurpThread t = new BurpThread(errors::add);
        CountDownLatch done = new CountDownLatch(2);
        String caller = Thread.currentThread().getName();
        t.execute(() -> {
            ran.add("a " + !Thread.currentThread().getName().equals(caller));
            done.countDown();
        });
        t.execute(() -> {
            ran.add("b");
            done.countDown();
        });
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(List.of("a true", "b"), ran);
        t.close();
    }

    @Test
    void aFailingTaskIsLoggedAndTheNextStillRuns() throws Exception {
        BurpThread t = new BurpThread(errors::add);
        CountDownLatch done = new CountDownLatch(1);
        t.execute(() -> {
            throw new IllegalStateException("Burp says no");
        });
        t.execute(done::countDown);
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(List.of("Hirdman Radar: java.lang.IllegalStateException: Burp says no"), errors);
        t.close();
    }

    @Test
    void afterCloseTasksAreDroppedQuietly() {
        BurpThread t = new BurpThread(errors::add);
        t.close();
        t.execute(() -> ran.add("late"));
        assertEquals(List.of(), ran);
        assertEquals(List.of(), errors);
    }
}
