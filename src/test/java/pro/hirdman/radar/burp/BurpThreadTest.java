package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
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

    final List<Throwable> causes = new CopyOnWriteArrayList<>();

    /** Burp's logToError(String, Throwable): the message and its cause apart. */
    void error(String message, Throwable cause) {
        errors.add(message);
        causes.add(cause);
    }

    @Test
    void runsTasksInOrderOffTheCallersThread() throws Exception {
        BurpThread t = new BurpThread(this::error);
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
        t.close(Duration.ofSeconds(1));
    }

    @Test
    void aFailingTaskIsLoggedAndTheNextStillRuns() throws Exception {
        BurpThread t = new BurpThread(this::error);
        CountDownLatch done = new CountDownLatch(1);
        t.execute(() -> {
            throw new IllegalStateException("Burp says no");
        });
        t.execute(done::countDown);
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(List.of("Hirdman Radar: a call into Burp failed"), errors);
        assertEquals("Burp says no", causes.get(0).getMessage(), "the stack goes to the Errors tab");
        t.close(Duration.ofSeconds(1));
    }

    @Test
    void afterCloseTasksAreDroppedQuietly() {
        BurpThread t = new BurpThread(this::error);
        t.close(Duration.ofSeconds(1));
        t.execute(() -> ran.add("late"));
        assertEquals(List.of(), ran);
        assertEquals(List.of(), errors);
    }

    @Test
    void closeLetsQueuedTasksFinishWithinTheBudget() throws Exception {
        // Issues queued just before unload used to be thrown away.
        BurpThread t = new BurpThread(this::error);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch go = new CountDownLatch(1);
        t.execute(() -> {
            started.countDown();
            try {
                go.await();
            } catch (InterruptedException e) {
                ran.add("interrupted");
            }
        });
        t.execute(() -> ran.add("queued"));
        assertTrue(started.await(5, TimeUnit.SECONDS));
        go.countDown();
        t.close(Duration.ofSeconds(2));
        assertEquals(List.of("queued"), ran);
    }

    @Test
    void closeReturnsWhenTheBudgetRunsOut() throws Exception {
        BurpThread t = new BurpThread(this::error);
        CountDownLatch started = new CountDownLatch(1);
        t.execute(() -> {
            started.countDown();
            try {
                new CountDownLatch(1).await();
            } catch (InterruptedException e) {
                ran.add("interrupted");
            }
        });
        t.execute(() -> ran.add("never"));
        assertTrue(started.await(5, TimeUnit.SECONDS));
        long begin = System.nanoTime();
        t.close(Duration.ofMillis(200));
        assertTrue(System.nanoTime() - begin < Duration.ofSeconds(2).toNanos());
        assertTrue(ran.isEmpty() || ran.equals(List.of("interrupted")), ran.toString());
    }
}
