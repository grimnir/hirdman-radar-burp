package pro.hirdman.radar.jobs;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.api.Radar;

/** Cancellation of one run of a job, and the live server job that run started. */
public final class CancelToken {

    /** A server job and the client of the server it was created on, so a delete goes there even after a URL change. */
    public record ServerJob(Radar radar, String id) {
    }

    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final List<Runnable> hooks = new CopyOnWriteArrayList<>();
    private volatile @Nullable ServerJob serverJob;

    public void cancel() {
        if (cancelled.compareAndSet(false, true)) {
            hooks.forEach(Runnable::run);
        }
    }

    public boolean cancelled() {
        return cancelled.get();
    }

    /** Runs {@code hook} on cancel, or at once if already cancelled. */
    public void onCancel(Runnable hook) {
        hooks.add(hook);
        if (cancelled.get()) {
            hook.run();
        }
    }

    /** The server job still running for this run, or null. */
    public @Nullable ServerJob serverJob() {
        return serverJob;
    }

    void serverJob(@Nullable ServerJob job) {
        serverJob = job;
    }
}
