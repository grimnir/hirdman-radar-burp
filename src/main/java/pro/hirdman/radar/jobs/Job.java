package pro.hirdman.radar.jobs;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import pro.hirdman.radar.model.HostNames;

/** One plugin job as the Jobs strip shows it. State changes are reported to the queue. */
public final class Job {

    private static final AtomicLong IDS = new AtomicLong();

    private final long id = IDS.incrementAndGet();
    private final JobKind kind;
    private final String domain;
    private final List<String> hosts;
    private final boolean rescan;
    private final boolean recheck;
    private final boolean force;
    private final Consumer<Job> onChange;

    private volatile JobState state = JobState.WAITING;
    private volatile String status = StatusText.waiting();
    private volatile CancelToken token = newToken();
    /** A waiting job the worker does not take yet: a re-check before its delay is up. */
    private volatile boolean held;
    private boolean wakeRequested;

    Job(JobKind kind, String domain, List<String> hosts, boolean rescan, boolean recheck, Consumer<Job> onChange) {
        this(kind, domain, hosts, rescan, recheck, false, onChange);
    }

    /**
     * Hosts are normalized and de-duplicated; invalid names are dropped. {@code recheck} jobs never spawn another;
     * {@code force} jobs send hosts checked in the last 24 h too.
     */
    Job(JobKind kind, String domain, List<String> hosts, boolean rescan, boolean recheck, boolean force,
            Consumer<Job> onChange) {
        this.kind = kind;
        this.domain = domain == null ? null : HostNames.normalize(domain).orElse(domain);
        this.hosts = hosts.stream().map(HostNames::normalize).flatMap(Optional::stream).distinct().toList();
        this.rescan = rescan;
        this.recheck = recheck;
        this.force = force;
        this.onChange = onChange;
    }

    public long id() {
        return id;
    }

    public JobKind kind() {
        return kind;
    }

    /** The domain for domain jobs, null for host checks. */
    public String domain() {
        return domain;
    }

    public List<String> hosts() {
        return hosts;
    }

    public boolean rescan() {
        return rescan;
    }

    boolean recheck() {
        return recheck;
    }

    public boolean force() {
        return force;
    }

    /** The same request: kind, domain, host set and force; rescan is not compared. */
    boolean sameWork(Job other) {
        return kind == other.kind && force == other.force && Objects.equals(domain, other.domain)
                && Set.copyOf(hosts).equals(Set.copyOf(other.hosts));
    }

    public String label() {
        if (recheck) {
            return "Re-check failed";
        }
        if (kind == JobKind.CHECK_HOSTS) {
            return StatusText.hosts(hosts.size());
        }
        return domain;
    }

    public JobState state() {
        return state;
    }

    public String status() {
        return status;
    }

    CancelToken token() {
        return token;
    }

    /** Runner updates; ignored once the job is cancelled, so a late answer cannot revive it, and when nothing changes. */
    void update(JobState newState, String newStatus) {
        synchronized (this) {
            if (state == JobState.CANCELLED || state == newState && Objects.equals(status, newStatus)) {
                return;
            }
            state = newState;
            status = newStatus;
        }
        onChange.accept(this);
    }

    /** Marks the job cancelled; returns false if it had already finished. */
    boolean markCancelled(boolean notify) {
        synchronized (this) {
            if (state.finished()) {
                return false;
            }
            state = JobState.CANCELLED;
            status = StatusText.cancelled();
        }
        token.cancel();
        if (notify) {
            onChange.accept(this);
        }
        return true;
    }

    /** Keeps this waiting job from the worker until {@link #release}; the status says when it starts. */
    void hold(String waitStatus) {
        synchronized (this) {
            held = true;
            status = waitStatus;
        }
    }

    boolean held() {
        return held;
    }

    /** Lets a held job run; false if it was not held or has been cancelled meanwhile. */
    boolean release() {
        synchronized (this) {
            if (!held) {
                return false;
            }
            held = false;
            if (state != JobState.WAITING) {
                return false;
            }
            status = StatusText.waiting();
        }
        onChange.accept(this);
        return true;
    }

    /** Puts a failed job back to waiting with a fresh token; false if it had not failed. */
    boolean resetForRetry() {
        synchronized (this) {
            if (state != JobState.FAILED) {
                return false;
            }
            token = newToken();
            state = JobState.WAITING;
            status = StatusText.waiting();
        }
        onChange.accept(this);
        return true;
    }

    synchronized void wake() {
        wakeRequested = true;
        notifyAll();
    }

    /** True while a wake waits to end the next pause; for tests. */
    synchronized boolean wakePending() {
        return wakeRequested;
    }

    synchronized void pause(Duration d) throws InterruptedException {
        long deadline = System.nanoTime() + d.toNanos();
        long left;
        while (!wakeRequested && !token.cancelled() && (left = deadline - System.nanoTime()) > 0) {
            TimeUnit.NANOSECONDS.timedWait(this, left);
        }
        wakeRequested = false;
    }

    private CancelToken newToken() {
        CancelToken t = new CancelToken();
        t.onCancel(this::wake);
        return t;
    }
}
