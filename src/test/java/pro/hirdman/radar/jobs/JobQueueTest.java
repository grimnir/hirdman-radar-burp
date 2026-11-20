package pro.hirdman.radar.jobs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.jobs.FakeRadar.check;
import static pro.hirdman.radar.jobs.FakeRadar.done;
import static pro.hirdman.radar.jobs.FakeRadar.http;
import static pro.hirdman.radar.jobs.FakeRadar.page;
import static pro.hirdman.radar.jobs.FakeRadar.rootCheck;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import pro.hirdman.radar.Threads;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.model.ResultStore;

@Timeout(20)
class JobQueueTest {

    final FakeRadar radar = new FakeRadar();
    final ResultStore store = new ResultStore();
    final List<Duration> pauses = new CopyOnWriteArrayList<>();
    final AtomicInteger changes = new AtomicInteger();
    final List<String> events = new CopyOnWriteArrayList<>();
    final JobRunner.RunOptions options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, false, 5, true);
    /** Delayed tasks of the manual timer; they run only when a test runs them. */
    final List<Runnable> timed = new CopyOnWriteArrayList<>();
    final AtomicBoolean timerClosed = new AtomicBoolean();
    JobQueue queue;

    JobRunner runner(Sleeper sleeper, Radar r) {
        return new JobRunner(server -> r, store, new MetaGate(), sleeper, () -> options, events::add, e -> { }, () -> 0.5,
                System::nanoTime, Executors.newCachedThreadPool(Threads.daemon("test-http")));
    }

    /** Delays are recorded and skipped: a delayed task runs at once. */
    JobQueue queue(Sleeper sleeper) {
        queue = new JobQueue(runner(sleeper, radar), j -> changes.incrementAndGet(), (task, d) -> {
            pauses.add(d);
            task.run();
            return CompletableFuture.completedFuture(null);
        }, () -> timerClosed.set(true));
        return queue;
    }

    JobQueue fakeTimeQueue() {
        return queue((d, job) -> pauses.add(d));
    }

    /** Delays are recorded and their tasks kept in {@link #timed}. */
    JobQueue manualTimerQueue() {
        queue = new JobQueue(runner((d, job) -> pauses.add(d), radar), j -> changes.incrementAndGet(), (task, d) -> {
            pauses.add(d);
            timed.add(task);
            return new CompletableFuture<>();
        }, () -> timerClosed.set(true));
        return queue;
    }

    /**
     * One explicit step of the worker: a job that sends nothing goes through the queue and is taken off the list.
     * The worker runs jobs in order, so everything queued before it has been dealt with.
     */
    void drain(JobQueue q) throws InterruptedException {
        store.apply(null, new Check(false, "marker.example.com", 0, 0, 0, 0, 0, true, List.of()), Instant.now());
        Job marker = q.submit(JobKind.CHECK_HOSTS, null, List.of("marker.example.com"), false);
        waitUntil(() -> marker.state() == JobState.DONE);
        q.remove(marker);
    }

    @AfterEach
    void tearDown() {
        if (queue != null) {
            queue.shutdown();
        }
    }

    static void waitUntil(BooleanSupplier condition) throws InterruptedException {
        long end = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                throw new AssertionError("condition not met in 5 s");
            }
            Thread.sleep(10);
        }
    }

    @Test
    void onlyTheNewestFinishedJobsAreKept() throws Exception {
        // The traffic watcher queues a job a minute; a list that only grows slowed the Jobs strip over a long session.
        JobRunner failing = new JobRunner(() -> null, store, new MetaGate(), (d, j) -> { },
                () -> new JobRunner.RunOptions(null, "test", false, 5, true), e -> { }, e -> { });
        queue = new JobQueue(failing, () -> null, j -> { });
        List<Job> all = new java.util.ArrayList<>();
        for (int i = 0; i < JobQueue.KEEP_FINISHED + 5; i++) {
            all.add(queue.submit(JobKind.CHECK_HOSTS, null, List.of("h" + i + ".example.com"), false));
        }
        waitUntil(() -> all.stream().allMatch(j -> j.state().finished()));
        waitUntil(() -> queue.jobs().size() == JobQueue.KEEP_FINISHED);
        assertEquals(all.subList(5, all.size()), queue.jobs());
    }

    @Test
    void runsOneJobAtATime() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, true, rootCheck("a.com"), done(0, 0))));
        radar.polls.add(page(1, true, rootCheck("b.com"), done(0, 0)));
        JobQueue q = fakeTimeQueue();
        Job first = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        Job second = q.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        waitUntil(() -> first.state() == JobState.RUNNING && radar.calls.contains("poll j1 0"));
        assertEquals(JobState.WAITING, second.state());
        assertEquals("Waiting in plugin queue", second.status());
        release.countDown();
        waitUntil(() -> second.state() == JobState.DONE);
        assertEquals(JobState.DONE, first.state());
        assertEquals(List.of(first, second), q.jobs());
    }

    List<String> queueEvents() {
        return events.stream().filter(e -> e.contains("queued") || e.contains("already in the queue")).toList();
    }

    /** Holds the worker on a first domain job, so later jobs stay waiting. */
    Job holdWorker(JobQueue q, CountDownLatch release) throws Exception {
        radar.polls.add(new FakeRadar.Hang(release, page(1, true, rootCheck("hold.com"), done(0, 0))));
        Job first = q.submit(JobKind.FIND_AND_CHECK, "hold.com", List.of(), false);
        waitUntil(() -> radar.calls.contains("poll j1 0"));
        return first;
    }

    @Test
    void theSameJobIsQueuedOnce() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        JobQueue q = fakeTimeQueue();
        Job first = holdWorker(q, release);
        assertSame(first, q.submit(JobKind.FIND_AND_CHECK, "Hold.com", List.of(), true));
        Job hosts = q.submit(JobKind.CHECK_HOSTS, null, List.of("a.b.com", "c.b.com"), false);
        assertSame(hosts, q.submit(JobKind.CHECK_HOSTS, null, List.of("c.b.com", "a.b.com"), false));
        assertEquals(List.of(first, hosts), q.jobs());
        assertEquals(List.of("Hirdman Radar: queued leak check for hold.com",
                "Hirdman Radar: leak check for hold.com is already in the queue",
                "Hirdman Radar: queued leak check of 2 hosts",
                "Hirdman Radar: leak check of 2 hosts is already in the queue"), queueEvents());
        release.countDown();
    }

    @Test
    void checkAgainIsNotSwallowedByAPlainCheck() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        JobQueue q = fakeTimeQueue();
        holdWorker(q, release);
        Job plain = q.submit(JobKind.CHECK_HOSTS, null, List.of("a.b.com"), false);
        Job forced = q.checkAgain(List.of("a.b.com"));
        assertNotSame(plain, forced);
        assertFalse(plain.force());
        assertTrue(forced.force());
        assertEquals(JobKind.CHECK_HOSTS, forced.kind());
        assertSame(forced, q.checkAgain(List.of("a.b.com")));
        assertEquals(3, q.jobs().size());
        release.countDown();
    }

    @Test
    void aCancelledJobDoesNotBlockTheSameOne() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        JobQueue q = fakeTimeQueue();
        holdWorker(q, release);
        Job waiting = q.submit(JobKind.CHECK_HOSTS, null, List.of("a.b.com"), false);
        q.cancel(waiting);
        Job again = q.submit(JobKind.CHECK_HOSTS, null, List.of("a.b.com"), false);
        assertNotSame(waiting, again);
        assertEquals(JobState.WAITING, again.state());
        release.countDown();
    }

    @Test
    void retryNowSkipsTheWait() throws Exception {
        // A real pause of 30 s that Retry now must end.
        radar.starts.add(http(503, "", "Retry-After", "30"));
        radar.polls.add(page(1, true, rootCheck("a.com"), done(0, 0)));
        JobQueue q = queue(Sleeper.real());
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> j.state() == JobState.RETRYING);
        long t = System.nanoTime();
        q.retryNow(j);
        waitUntil(() -> j.state() == JobState.DONE);
        assertTrue(System.nanoTime() - t < Duration.ofSeconds(1).toNanos());
        assertEquals(2, radar.started.size());
    }

    @Test
    void cancelDeletesServerJobAndStartsNextWithoutWaitingForTheAnswer() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, false, check("x.a.com", true))));
        radar.polls.add(page(1, true, rootCheck("b.com"), done(0, 0)));
        JobQueue q = fakeTimeQueue();
        Job first = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        Job second = q.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        waitUntil(() -> radar.calls.contains("poll j1 0"));
        q.cancel(first);
        assertEquals(JobState.CANCELLED, first.state());
        assertEquals("Cancelled", first.status());
        waitUntil(() -> radar.deleted.contains("j1"));
        // The first poll still hangs: the queue does not wait for its answer.
        waitUntil(() -> second.state() == JobState.DONE);
        assertEquals(1, release.getCount());
        release.countDown();
        assertEquals(JobState.CANCELLED, first.state());
        assertTrue(store.host("x.a.com").isEmpty(), "a cancelled job writes no rows");
    }

    @Test
    void cancelDeletesOnTheServerTheJobWasCreatedOn() throws Exception {
        FakeRadar other = new FakeRadar();
        AtomicReference<Radar> current = new AtomicReference<>(radar);
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, false, check("x.a.com", true))));
        queue = new JobQueue(new JobRunner(server -> current.get(), store, new MetaGate(), (d, j) -> { }, () -> options,
                events::add, e -> { }), j -> { });
        Job first = queue.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> radar.calls.contains("poll j1 0"));
        // The Server URL changes while the job runs.
        current.set(other);
        queue.cancel(first);
        waitUntil(() -> radar.deleted.contains("j1"));
        assertEquals(List.of(), other.deleted);
        release.countDown();
    }

    @Test
    void cancelWhileWaitingNeverRuns() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, true, rootCheck("a.com"), done(0, 0))));
        JobQueue q = fakeTimeQueue();
        Job first = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        Job second = q.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        waitUntil(() -> radar.calls.contains("poll j1 0"));
        q.cancel(second);
        release.countDown();
        waitUntil(() -> first.state() == JobState.DONE);
        drain(q);
        assertEquals(1, radar.started.size());
        assertEquals(JobState.CANCELLED, second.state());
        assertTrue(radar.deleted.isEmpty());
    }

    @Test
    void retryOnlyFailedAndRemoveOnlyFinished() throws Exception {
        radar.starts.add(http(401, "{\"error\":\"unauthorized\"}"));
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, true, rootCheck("a.com"), done(0, 0))));
        JobQueue q = fakeTimeQueue();
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> j.state() == JobState.FAILED);
        q.retry(j);
        waitUntil(() -> j.state() == JobState.RUNNING && radar.calls.contains("poll j2 0"));
        q.remove(j);
        assertEquals(List.of(j), q.jobs(), "a running job stays");
        q.retry(j);
        release.countDown();
        waitUntil(() -> j.state() == JobState.DONE);
        drain(q);
        assertEquals(2, radar.started.size(), "retry of a running job does nothing");
        q.remove(j);
        assertEquals(List.of(), q.jobs());
    }

    @Test
    void shutdownReturnsWithinTwoSecondsWhilePollHangs() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(2, true, check("x.a.com", true, "high"), done(1, 0))));
        JobQueue q = fakeTimeQueue();
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> radar.calls.contains("poll j1 0"));
        int before = changes.get();
        long t = System.nanoTime();
        q.shutdown();
        assertTrue(System.nanoTime() - t < Duration.ofMillis(2500).toNanos());
        assertTrue(radar.deleted.contains("j1"));
        assertEquals(JobState.CANCELLED, j.state());
        waitUntil(() -> radar.calls.contains("interrupted"));
        release.countDown();
        assertTrue(q.awaitWorker(Duration.ofSeconds(5)));
        assertTrue(store.all().isEmpty());
        assertTrue(timerClosed.get());
        Job late = q.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        assertEquals(JobState.WAITING, late.state());
        assertEquals(1, radar.started.size());
        assertEquals(before, changes.get());
    }

    @Test
    void nothingIsReportedAfterShutdown() throws Exception {
        radar.starts.add(http(401, "{\"error\":\"unauthorized\"}"));
        JobQueue q = fakeTimeQueue();
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> j.state() == JobState.FAILED);
        q.shutdown();
        assertTrue(q.awaitWorker(Duration.ofSeconds(5)));
        int before = changes.get();
        int logged = events.size();
        q.retry(j);
        q.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        assertEquals(before, changes.get());
        assertEquals(logged, events.size());
        assertEquals(1, radar.started.size());
    }

    @Test
    void retryNowIgnoresAJobThatIsNotRetrying() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, false, rootCheck("a.com"))));
        radar.polls.add(page(2, true, done(0, 0)));
        List<Boolean> cutShort = new CopyOnWriteArrayList<>();
        JobQueue q = queue((d, job) -> {
            pauses.add(d);
            cutShort.add(job.wakePending());
        });
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> radar.calls.contains("poll j1 0"));
        q.retryNow(j);
        release.countDown();
        waitUntil(() -> j.state() == JobState.DONE);
        assertEquals(List.of(JobRunner.POLL_PAUSE), pauses);
        assertEquals(List.of(false), cutShort, "the pause between pages is not cut short");
    }

    /** Runs a domain job with one unchecked host; returns the re-check waiting for its delay. */
    Job pendingRecheck(JobQueue q) throws InterruptedException {
        radar.polls.add(page(2, true, rootCheck("a.com"), check("x.a.com", false), done(1, 1)));
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> j.state() == JobState.DONE && q.jobs().size() == 2);
        return q.jobs().get(1);
    }

    @Test
    void aPendingRecheckWaitsInTheListAndCanBeCancelled() throws Exception {
        JobQueue q = manualTimerQueue();
        Job recheck = pendingRecheck(q);
        assertEquals(JobState.WAITING, recheck.state());
        assertEquals("Retry in 2 min", recheck.status());
        assertEquals(List.of(JobRunner.RECHECK_DELAY), pauses.stream().filter(JobRunner.RECHECK_DELAY::equals).toList());
        drain(q);
        assertEquals(JobState.WAITING, recheck.state(), "a held re-check is not taken before its time");
        q.cancel(recheck);
        timed.forEach(Runnable::run);
        drain(q);
        assertEquals(JobState.CANCELLED, recheck.state());
        assertEquals(1, radar.started.size());
    }

    @Test
    void aRecheckRunsWhenItsTimeComes() throws Exception {
        JobQueue q = manualTimerQueue();
        Job recheck = pendingRecheck(q);
        radar.polls.add(page(1, true, check("x.a.com", true), done(1, 0)));
        timed.forEach(Runnable::run);
        waitUntil(() -> recheck.state() == JobState.DONE);
        assertEquals(2, radar.started.size());
    }

    @Test
    void aHeldRecheckDoesNotHoldBackTheSameCheckAskedNow() throws Exception {
        JobQueue q = manualTimerQueue();
        Job recheck = pendingRecheck(q);
        Job now = q.submit(JobKind.CHECK_HOSTS, null, List.of("x.a.com"), false);
        assertNotSame(recheck, now);
        radar.polls.add(page(1, true, check("x.a.com", true), done(1, 0)));
        waitUntil(() -> now.state() == JobState.DONE);
        assertEquals(JobState.WAITING, recheck.state());
    }

    @Test
    void shutdownDropsAPendingRecheck() throws Exception {
        JobQueue q = manualTimerQueue();
        Job recheck = pendingRecheck(q);
        q.shutdown();
        assertTrue(timerClosed.get());
        assertEquals(JobState.CANCELLED, recheck.state());
        timed.forEach(Runnable::run);
        assertTrue(q.awaitWorker(Duration.ofSeconds(5)));
        assertEquals(1, radar.started.size());
    }

    @Test
    void notCheckedAreRecheckedOnceAfterTwoMinutes() throws Exception {
        radar.polls.add(page(2, true, rootCheck("a.com"), check("x.a.com", false), done(1, 1)));
        radar.polls.add(page(1, true, check("x.a.com", false), done(1, 1)));
        JobQueue q = fakeTimeQueue();
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> q.jobs().size() == 2 && q.jobs().get(1).state() == JobState.DONE);
        Job recheck = q.jobs().get(1);
        assertEquals("Re-check failed", recheck.label());
        assertEquals(List.of("x.a.com"), recheck.hosts());
        assertTrue(pauses.contains(Duration.ofMinutes(2)), pauses.toString());
        assertEquals(List.of("Hirdman Radar: queued leak check for a.com", "Hirdman Radar: queued re-check of 1 host"),
                events.stream().filter(e -> e.contains("queued")).toList());
        drain(q);
        assertEquals(2, q.jobs().size());
        assertEquals(JobState.DONE, j.state());
    }

    @Test
    void noRecheckIsScheduledAfterShutdown() throws Exception {
        radar.polls.add(page(2, true, rootCheck("a.com"), check("x.a.com", false), done(1, 1)));
        AtomicReference<JobQueue> self = new AtomicReference<>();
        // Unload lands right as the job finishes, before the worker schedules its recheck.
        queue = new JobQueue(runner((d, j) -> { }, radar), j -> {
            if (j.state() == JobState.DONE) {
                self.get().shutdown();
            }
        }, (task, d) -> {
            timed.add(task);
            return new CompletableFuture<>();
        }, () -> { });
        self.set(queue);
        Job j = queue.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> j.state() == JobState.DONE);
        assertTrue(queue.awaitWorker(Duration.ofSeconds(5)));
        assertEquals(List.of(), timed);
        assertEquals(List.of(j), queue.jobs());
    }

    @Test
    void anErrorInARunFailsTheJobAndTheWorkerGoesOn() throws Exception {
        // An Error used to end the only worker silently, leaving every job waiting.
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicBoolean crash = new AtomicBoolean(true);
        JobRunner runner = new JobRunner(server -> {
            if (crash.getAndSet(false)) {
                throw new StackOverflowError("deep");
            }
            return radar;
        }, store, new MetaGate(), (d, j) -> { }, () -> options, events::add, errors::add);
        queue = new JobQueue(runner, j -> { });
        radar.polls.add(page(1, true, rootCheck("b.com"), done(0, 0)));
        Job first = queue.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        Job second = queue.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        waitUntil(() -> second.state() == JobState.DONE);
        assertEquals(JobState.FAILED, first.state());
        assertEquals("Failed: Unexpected error. Details are in the extension's Errors tab.", first.status());
        assertTrue(errors.stream().anyMatch(e -> e.startsWith("Hirdman Radar: unexpected error in a.com: java.lang.StackOverflowError: deep")),
                errors.toString());
    }

    @Test
    void removeFinishedKeepsWaitingAndRunningJobs() throws Exception {
        JobQueue q = fakeTimeQueue();
        radar.polls.add(page(1, true, rootCheck("a.com"), done(0, 0)));
        Job finished = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> finished.state() == JobState.DONE);
        CountDownLatch release = new CountDownLatch(1);
        Job running = holdWorker(q, release);
        Job waiting = q.submit(JobKind.CHECK_HOSTS, null, List.of("x.b.com"), false);
        int before = changes.get();
        q.removeFinished();
        assertEquals(List.of(running, waiting), q.jobs());
        assertTrue(changes.get() > before);
        release.countDown();
    }
}
