package pro.hirdman.radar.jobs;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import pro.hirdman.radar.Threads;
import pro.hirdman.radar.api.Radar;

/** Plugin job queue: one job runs at a time on a background thread, never on the Swing thread. */
public final class JobQueue {

    private static final Duration CANCEL_DELETE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration SHUTDOWN_BUDGET = Duration.ofSeconds(2);
    /** Finished jobs shown in the Jobs strip; older ones drop off, waiting and running ones always stay. */
    static final int KEEP_FINISHED = 50;

    /** Runs a task after a delay; tests pass their own clock. */
    @FunctionalInterface
    interface Timer {
        void schedule(Runnable task, Duration delay);
    }

    private final JobRunner runner;
    private final Consumer<Job> onChange;
    private final Timer timer;
    private final Runnable closeTimer;
    private final List<Job> jobs = new ArrayList<>();
    private final Thread worker;
    private volatile boolean closed;
    private Job current;

    public JobQueue(JobRunner runner, Consumer<Job> onChange) {
        this(runner, onChange, Executors.newSingleThreadScheduledExecutor(Threads.daemon("hirdman-radar-timer")));
    }

    /** Kept for existing callers: a delete now goes to the server the job was created on, so {@code radar} is unused. */
    public JobQueue(JobRunner runner, Supplier<Radar> radar, Consumer<Job> onChange) {
        this(runner, onChange);
    }

    private JobQueue(JobRunner runner, Consumer<Job> onChange, ScheduledExecutorService timer) {
        this(runner, onChange, (task, delay) -> timer.schedule(task, delay.toNanos(), TimeUnit.NANOSECONDS),
                timer::shutdownNow);
    }

    JobQueue(JobRunner runner, Consumer<Job> onChange, Timer timer, Runnable closeTimer) {
        this.runner = runner;
        this.onChange = onChange;
        this.timer = timer;
        this.closeTimer = closeTimer;
        this.worker = Threads.daemon("hirdman-radar-jobs").newThread(this::work);
        worker.start();
    }

    /** Queues a job, or returns the same one already waiting or running. */
    public Job submit(JobKind kind, String domain, List<String> hosts, boolean rescan) {
        return add(new Job(kind, domain, hosts, rescan, false, this::changed));
    }

    /** A host check that also sends hosts checked in the last 24 h. */
    public Job checkAgain(List<String> hosts) {
        return add(new Job(JobKind.CHECK_HOSTS, null, hosts, false, false, true, this::changed));
    }

    /** What a plain check of these hosts would send; for the "more than 50" question. */
    public List<String> toSend(List<String> hosts) {
        return runner.toSend(hosts);
    }

    public synchronized List<Job> jobs() {
        return List.copyOf(jobs);
    }

    /** Stops a waiting or running job; the server job, if any, is deleted in the background. */
    public void cancel(Job job) {
        if (!job.markCancelled(true)) {
            return;
        }
        // Read after markCancelled: a runner that sets the job later sees the cancel and deletes it itself.
        CancelToken.ServerJob serverJob = job.token().serverJob();
        if (serverJob != null) {
            Threads.daemon("hirdman-radar-cancel").newThread(
                    () -> JobRunner.deleteQuietly(serverJob.radar(), serverJob.id(), CANCEL_DELETE_TIMEOUT)).start();
        }
    }

    /** Ends the current wait of a retrying job. */
    public void retryNow(Job job) {
        if (job.state() == JobState.RETRYING) {
            job.wake();
        }
    }

    /** Puts a failed job back in the queue. */
    public void retry(Job job) {
        if (job.resetForRetry()) {
            synchronized (this) {
                notifyAll();
            }
        }
    }

    /** Removes a finished job from the list; jobs still waiting or running stay. */
    public void remove(Job job) {
        boolean removed;
        synchronized (this) {
            removed = job.state().finished() && jobs.remove(job);
        }
        if (removed) {
            changed(job);
        }
    }

    /** Takes every finished job off the list; waiting and running ones stay. */
    public void removeFinished() {
        List<Job> gone;
        synchronized (this) {
            gone = jobs.stream().filter(j -> j.state().finished()).toList();
            jobs.removeAll(gone);
        }
        gone.forEach(this::changed);
    }

    /** Extension unload: cancels everything quietly and returns within about two seconds. */
    public void shutdown() {
        List<Job> all;
        Job running;
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            all = new ArrayList<>(jobs);
            running = current;
            notifyAll();
        }
        closeTimer.run();
        all.forEach(j -> j.markCancelled(false));
        CancelToken.ServerJob serverJob = running == null ? null : running.token().serverJob();
        // The worker is not waited for: a hanging request may ignore the interrupt, and its run is cancelled anyway.
        worker.interrupt();
        runner.close();
        if (serverJob != null) {
            Thread delete = Threads.daemon("hirdman-radar-unload").newThread(
                    () -> JobRunner.deleteQuietly(serverJob.radar(), serverJob.id(), SHUTDOWN_BUDGET));
            delete.start();
            try {
                delete.join(SHUTDOWN_BUDGET.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Waits for the worker to end after {@link #shutdown}; for tests. */
    boolean awaitWorker(Duration d) throws InterruptedException {
        worker.join(d.toMillis());
        return !worker.isAlive();
    }

    private void work() {
        while (true) {
            Job job;
            try {
                job = take();
            } catch (InterruptedException e) {
                return;
            }
            if (job == null) {
                return;
            }
            List<String> again = run(job);
            boolean pruned;
            synchronized (this) {
                current = null;
                pruned = pruneFinished();
            }
            if (pruned) {
                changed(job);
            }
            if (!again.isEmpty()) {
                scheduleRecheck(again);
            }
        }
    }

    /** Whatever the run throws, the job ends and the worker goes on with the next one. */
    private List<String> run(Job job) {
        try {
            return runner.run(job, job.token());
        } catch (Throwable t) {
            // An Error (stack overflow, out of memory, a missing class) used to end the only worker silently.
            job.update(JobState.FAILED, StatusText.failed(JobRunner.CRASHED));
            try {
                runner.crashed(job, t);
            } catch (Throwable again) {
                // Logging failed too; the job is already marked failed.
            }
            return List.of();
        }
    }

    private boolean pruneFinished() {
        long extra = jobs.stream().filter(j -> j.state().finished()).count() - KEEP_FINISHED;
        boolean pruned = false;
        for (Iterator<Job> it = jobs.iterator(); extra > 0 && it.hasNext();) {
            if (it.next().state().finished()) {
                it.remove();
                extra--;
                pruned = true;
            }
        }
        return pruned;
    }

    /** The next waiting job, or null once the queue is closed. */
    private synchronized Job take() throws InterruptedException {
        while (!closed) {
            Job next = nextWaiting();
            if (next != null) {
                current = next;
                return next;
            }
            wait();
        }
        return null;
    }

    private Job nextWaiting() {
        return jobs.stream().filter(j -> j.state() == JobState.WAITING && !j.held()).findFirst().orElse(null);
    }

    /** Hosts the server could not check get one more try, as a job of their own that waits in the list, cancellable. */
    private void scheduleRecheck(List<String> hosts) {
        if (closed) {
            return;
        }
        Job recheck = new Job(JobKind.CHECK_HOSTS, null, hosts, false, true, this::changed);
        recheck.hold(StatusText.recheckIn(JobRunner.RECHECK_DELAY));
        if (add(recheck) != recheck) {
            return;
        }
        try {
            timer.schedule(() -> release(recheck), JobRunner.RECHECK_DELAY);
        } catch (RejectedExecutionException e) {
            // Unloading: the queue is closed and the job cancelled.
        }
    }

    private void release(Job recheck) {
        if (recheck.release()) {
            synchronized (this) {
                notifyAll();
            }
        }
    }

    /** Queues the job unless the queue is closed; an active job doing the same work is returned instead. */
    private Job add(Job job) {
        Job same;
        synchronized (this) {
            if (closed) {
                return job;
            }
            // A held re-check does not swallow a check the user asks for now.
            same = jobs.stream().filter(j -> !j.state().finished() && !j.held() && j.sameWork(job)).findFirst().orElse(null);
            if (same == null) {
                jobs.add(job);
                notifyAll();
            }
        }
        if (same != null) {
            runner.alreadyQueued(same);
            return same;
        }
        runner.queued(job);
        changed(job);
        return job;
    }

    private void changed(Job job) {
        if (!closed) {
            onChange.accept(job);
        }
    }
}
