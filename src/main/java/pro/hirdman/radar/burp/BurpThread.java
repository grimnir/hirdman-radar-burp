package pro.hirdman.radar.burp;

import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import pro.hirdman.radar.Threads;

/** One background thread for calls into Burp (issues, site map), so job polling never waits on Burp. */
public final class BurpThread implements Executor {

    private final ExecutorService service = Executors.newSingleThreadExecutor(Threads.daemon("hirdman-radar-burp"));
    private final BiConsumer<String, Throwable> error;

    public BurpThread(BiConsumer<String, Throwable> error) {
        this.error = error;
    }

    /** A failing task is logged and the next one still runs; after close, tasks are dropped. */
    @Override
    public void execute(Runnable task) {
        try {
            service.execute(() -> {
                try {
                    task.run();
                } catch (RuntimeException e) {
                    error.accept("Hirdman Radar: a call into Burp failed", e);
                }
            });
        } catch (RejectedExecutionException e) {
            // Unloading.
        }
    }

    /** Unload: tasks already queued (issues of rows just checked) get up to {@code wait} to finish, then are dropped. */
    public void close(Duration wait) {
        service.shutdown();
        try {
            if (service.awaitTermination(wait.toNanos(), TimeUnit.NANOSECONDS)) {
                return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        service.shutdownNow();
    }
}
