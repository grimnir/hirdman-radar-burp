package pro.hirdman.radar.jobs;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/** Cancellation of one run of a job, and the id of the last server job that run started. */
public final class CancelToken {

    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final List<Runnable> hooks = new CopyOnWriteArrayList<>();
    private volatile String serverJobId;

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

    public String serverJobId() {
        return serverJobId;
    }

    void serverJobId(String id) {
        serverJobId = id;
    }
}
