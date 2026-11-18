package pro.hirdman.radar.jobs;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;
import pro.hirdman.radar.api.Radar;

/** Plugin job queue: one job runs at a time on a background thread, never on the Swing thread. */
public final class JobQueue {

    private static final Duration CANCEL_DELETE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration SHUTDOWN_BUDGET = Duration.ofSeconds(2);
    /** Finished jobs shown in the Jobs strip; older ones drop off, waiting and running ones always stay. */
    static final int KEEP_FINISHED = 50;

    private final JobRunner runner;
    private final Supplier<Radar> radar;
    private final Consumer<Job> onChange;
    private final List<Job> jobs = new ArrayList<>();
    private final List<Job> pendingRechecks = new ArrayList<>();
    private final Thread worker;
    private volatile boolean closed;
    private Job current;

    public JobQueue(JobRunner runner, Supplier<Radar> radar, Consumer<Job> onChange) {
        this.runner = runner;
        this.radar = radar;
        this.onChange = onChange;
        this.worker = daemon("hirdman-radar-jobs", this::work);
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
        // Read after markCancelled: a runner that sets the id later sees the cancel and deletes it itself.
        String serverJobId = job.token().serverJobId();
        if (serverJobId != null) {
            daemon("hirdman-radar-cancel",
                    () -> JobRunner.deleteQuietly(radar.get(), serverJobId, CANCEL_DELETE_TIMEOUT)).start();
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
            all.addAll(pendingRechecks);
            running = current;
            notifyAll();
        }
        all.forEach(j -> j.markCancelled(false));
        String serverJobId = running == null ? null : running.token().serverJobId();
        // The worker is not waited for: a hanging request may ignore the interrupt, and its run is cancelled anyway.
        worker.interrupt();
        if (serverJobId != null) {
            Thread delete = daemon("hirdman-radar-unload",
                    () -> JobRunner.deleteQuietly(radar.get(), serverJobId, SHUTDOWN_BUDGET));
            delete.start();
            try {
                delete.join(SHUTDOWN_BUDGET.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
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
            List<String> again = runner.run(job, job.token());
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
        return jobs.stream().filter(j -> j.state() == JobState.WAITING).findFirst().orElse(null);
    }

    /** Hosts the server could not check get one more try, as a job of their own, after a pause. */
    private void scheduleRecheck(List<String> hosts) {
        Job recheck = new Job(JobKind.CHECK_HOSTS, null, hosts, false, true, this::changed);
        synchronized (this) {
            if (closed) {
                return;
            }
            pendingRechecks.add(recheck);
        }
        daemon("hirdman-radar-recheck", () -> {
            try {
                runner.sleeper().sleep(JobRunner.RECHECK_DELAY, recheck);
            } catch (InterruptedException e) {
                return;
            } finally {
                synchronized (this) {
                    pendingRechecks.remove(recheck);
                }
            }
            add(recheck);
        }).start();
    }

    /** Queues the job unless the queue is closed; an active job doing the same work is returned instead. */
    private Job add(Job job) {
        Job same;
        synchronized (this) {
            if (closed) {
                return job;
            }
            same = jobs.stream().filter(j -> !j.state().finished() && j.sameWork(job)).findFirst().orElse(null);
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

    private static Thread daemon(String name, Runnable body) {
        Thread t = new Thread(body, name);
        t.setDaemon(true);
        return t;
    }
}
