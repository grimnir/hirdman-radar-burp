package pro.hirdman.radar.burp;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Consumer;

/** One background thread for calls into Burp (issues, site map), so job polling never waits on Burp. */
public final class BurpThread implements Executor {

    private final ExecutorService service = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "hirdman-radar-burp");
        t.setDaemon(true);
        return t;
    });
    private final Consumer<String> error;

    public BurpThread(Consumer<String> error) {
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
                    error.accept("Hirdman Radar: " + e);
                }
            });
        } catch (RejectedExecutionException e) {
            // Unloading.
        }
    }

    public void close() {
        service.shutdownNow();
    }
}
