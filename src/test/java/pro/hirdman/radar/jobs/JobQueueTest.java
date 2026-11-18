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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import pro.hirdman.radar.model.ResultStore;

@Timeout(20)
class JobQueueTest {

    final FakeRadar radar = new FakeRadar();
    final ResultStore store = new ResultStore();
    final List<Duration> pauses = new CopyOnWriteArrayList<>();
    final AtomicInteger changes = new AtomicInteger();
    final List<String> events = new CopyOnWriteArrayList<>();
    final JobRunner.RunOptions options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, false, 5, true);
    JobQueue queue;

    JobQueue queue(Sleeper sleeper) {
        JobRunner runner = new JobRunner(() -> radar, store, new MetaGate(), sleeper, () -> options, events::add, e -> { }, () -> 0.5);
        queue = new JobQueue(runner, () -> radar, j -> changes.incrementAndGet());
        return queue;
    }

    JobQueue fakeTimeQueue() {
        return queue((d, job) -> pauses.add(d));
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
    void cancelDeletesServerJobAndStartsNext() throws Exception {
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
        assertEquals(JobState.WAITING, second.state());
        release.countDown();
        waitUntil(() -> second.state() == JobState.DONE);
        assertEquals(JobState.CANCELLED, first.state());
        assertTrue(store.host("x.a.com").isEmpty(), "a cancelled job writes no rows");
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
        Thread.sleep(100);
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
        Thread.sleep(100);
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
        Thread.sleep(300);
        assertTrue(store.all().isEmpty());
        Job late = q.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        Thread.sleep(100);
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
        int before = changes.get();
        int logged = events.size();
        q.retry(j);
        q.submit(JobKind.FIND_AND_CHECK, "b.com", List.of(), false);
        Thread.sleep(100);
        assertEquals(before, changes.get());
        assertEquals(logged, events.size());
        assertEquals(1, radar.started.size());
    }

    @Test
    void retryNowIgnoresAJobThatIsNotRetrying() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, false, rootCheck("a.com"))));
        radar.polls.add(page(2, true, done(0, 0)));
        JobQueue q = queue(Sleeper.real());
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> radar.calls.contains("poll j1 0"));
        q.retryNow(j);
        long t = System.nanoTime();
        release.countDown();
        waitUntil(() -> j.state() == JobState.DONE);
        assertTrue(System.nanoTime() - t >= Duration.ofMillis(1900).toNanos(), "the 2 s pause between pages still runs");
    }

    @Test
    void shutdownDropsAPendingRecheck() throws Exception {
        CountDownLatch inPause = new CountDownLatch(1);
        CountDownLatch wake = new CountDownLatch(1);
        radar.polls.add(page(2, true, rootCheck("a.com"), check("x.a.com", false), done(1, 1)));
        JobQueue q = queue((d, job) -> {
            pauses.add(d);
            if (d.equals(JobRunner.RECHECK_DELAY)) {
                inPause.countDown();
                wake.await();
            }
        });
        Job j = q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        assertTrue(inPause.await(5, TimeUnit.SECONDS));
        q.shutdown();
        wake.countDown();
        Thread.sleep(100);
        assertEquals(List.of(j), q.jobs());
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
        Thread.sleep(200);
        assertEquals(2, q.jobs().size());
        assertEquals(JobState.DONE, j.state());
    }

    @Test
    void shutdownEndsTheRecheckWait() throws Exception {
        radar.polls.add(page(2, true, rootCheck("a.com"), check("x.a.com", false), done(1, 1)));
        JobQueue q = queue(Sleeper.real());
        q.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> recheckThreads() == 1);
        q.shutdown();
        waitUntil(() -> recheckThreads() == 0);
    }

    static long recheckThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.isAlive() && t.getName().equals("hirdman-radar-recheck")).count();
    }

    @Test
    void noRecheckIsScheduledAfterShutdown() throws Exception {
        radar.polls.add(page(2, true, rootCheck("a.com"), check("x.a.com", false), done(1, 1)));
        JobRunner runner = new JobRunner(() -> radar, store, new MetaGate(), Sleeper.real(), () -> options, e -> { }, e -> { }, () -> 0.5);
        AtomicReference<JobQueue> self = new AtomicReference<>();
        // Unload lands right as the job finishes, before the worker schedules its recheck.
        queue = new JobQueue(runner, () -> radar, j -> {
            if (j.state() == JobState.DONE) {
                self.get().shutdown();
            }
        });
        self.set(queue);
        Job j = queue.submit(JobKind.FIND_AND_CHECK, "a.com", List.of(), false);
        waitUntil(() -> j.state() == JobState.DONE);
        Thread.sleep(200);
        assertEquals(0, recheckThreads());
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
