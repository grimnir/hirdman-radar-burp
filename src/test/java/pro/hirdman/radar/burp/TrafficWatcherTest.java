package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobRunner;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.Sleeper;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.traffic.NewHostBatcher;

class TrafficWatcherTest {

    static final Instant T0 = Instant.parse("2026-11-17T12:00:00Z");

    // An invalid server makes every queued job fail at once, so nothing reaches the network.
    final JobRunner runner = new JobRunner(() -> null, new ResultStore(), new MetaGate(), Sleeper.real(), this::runOptions,
            e -> { }, e -> { });
    /** While set, the queue's worker waits in its job, so the job stays queued. */
    volatile java.util.concurrent.CountDownLatch hold;

    JobRunner.RunOptions runOptions() {
        java.util.concurrent.CountDownLatch h = hold;
        if (h != null) {
            try {
                h.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return new JobRunner.RunOptions(null, "test", false, 5, true);
    }
    final JobQueue queue = new JobQueue(runner, () -> null, j -> { });
    final AtomicBoolean enabled = new AtomicBoolean(true);
    final List<String> errors = new CopyOnWriteArrayList<>();
    final RequestToBeSentAction sent = fake(RequestToBeSentAction.class, Map.of());
    final ResponseReceivedAction received = fake(ResponseReceivedAction.class, Map.of());
    final List<Object> passed = new CopyOnWriteArrayList<>();
    final List<HttpResponseReceived> looked = new CopyOnWriteArrayList<>();
    java.util.function.Consumer<HttpResponseReceived> responses = looked::add;
    NewHostBatcher batcher = new NewHostBatcher(Duration.ofSeconds(60), Duration.ofHours(24), h -> Optional.empty(),
            () -> "scan.hirdman.pro");
    TrafficWatcher watcher;

    TrafficWatcher watcher() {
        if (watcher == null) {
            watcher = new TrafficWatcher(batcher, enabled::get, queue, errors::add, r -> responses.accept(r), r -> {
                passed.add(r);
                return sent;
            }, r -> {
                passed.add(r);
                return received;
            });
        }
        return watcher;
    }

    @AfterEach
    void tearDown() {
        if (watcher != null) {
            watcher.close();
        }
        queue.shutdown();
    }

    static HttpRequestToBeSent request(String host, boolean inScope, ToolType tool) {
        return request(host, inScope, tool, new java.util.concurrent.atomic.AtomicInteger());
    }

    static HttpRequestToBeSent request(String host, boolean inScope, ToolType tool,
            java.util.concurrent.atomic.AtomicInteger scopeAsked) {
        ToolSource source = fake(ToolSource.class, (m, a) -> switch (m) {
            case "toolType" -> tool;
            case "isFromTool" -> Arrays.asList((ToolType[]) a[0]).contains(tool);
            default -> Fakes.DEFAULT;
        });
        HttpService service = fake(HttpService.class, Map.of("host", host));
        return fake(HttpRequestToBeSent.class, (m, a) -> switch (m) {
            case "toolSource" -> source;
            case "httpService" -> service;
            case "isInScope" -> {
                scopeAsked.incrementAndGet();
                yield inScope;
            }
            default -> Fakes.DEFAULT;
        });
    }

    @Test
    void aRequestThatCannotBeReadStillPassesAndIsLoggedOnce() {
        HttpRequestToBeSent broken = fake(HttpRequestToBeSent.class, (m, a) -> {
            throw new IllegalStateException("broken " + m);
        });
        assertSame(sent, watcher().handleHttpRequestToBeSent(broken));
        assertSame(sent, watcher().handleHttpRequestToBeSent(broken));
        assertEquals(List.of(broken, broken), passed);
        assertEquals(1, errors.size(), errors.toString());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: traffic check skipped a request: "), errors.get(0));
        assertTrue(errors.get(0).contains("broken toolSource"), errors.get(0));
    }

    static HttpResponseReceived response(ToolType tool) {
        ToolSource source = fake(ToolSource.class, (m, a) -> switch (m) {
            case "isFromTool" -> Arrays.asList((ToolType[]) a[0]).contains(tool);
            default -> Fakes.DEFAULT;
        });
        return fake(HttpResponseReceived.class, Map.of("toolSource", source));
    }

    @Test
    void responsesAreLookedAtExceptTheRadarsOwnAndPassUnchanged() {
        enabled.set(false);
        HttpResponseReceived proxy = response(ToolType.PROXY);
        HttpResponseReceived own = response(ToolType.EXTENSIONS);
        assertSame(received, watcher().handleHttpResponseReceived(proxy));
        assertSame(received, watcher().handleHttpResponseReceived(own));
        assertEquals(List.of(proxy), looked);
        responses = r -> {
            throw new IllegalStateException("odd response");
        };
        assertSame(received, watcher().handleHttpResponseReceived(proxy));
        assertSame(received, watcher().handleHttpResponseReceived(proxy));
        assertEquals(List.of(proxy, own, proxy, proxy), passed);
        assertEquals(1, errors.size(), errors.toString());
        assertTrue(errors.get(0).contains("odd response"), errors.get(0));
    }

    @Test
    void requestsPassUnchanged() {
        HttpRequestToBeSent r = request("a.example.com", true, ToolType.PROXY);
        assertSame(sent, watcher().handleHttpRequestToBeSent(r));
        HttpResponseReceived resp = fake(HttpResponseReceived.class, Map.of());
        assertSame(received, watcher().handleHttpResponseReceived(resp));
        assertEquals(List.of(r, resp), passed);
    }

    @Test
    void inScopeHostsBecomeOneHostCheck() {
        watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY));
        watcher().handleHttpRequestToBeSent(request("b.example.com", true, ToolType.REPEATER));
        watcher().handleHttpRequestToBeSent(request("c.example.com", false, ToolType.PROXY));
        watcher().drainNow(T0);
        List<Job> jobs = queue.jobs();
        assertEquals(1, jobs.size());
        assertEquals(JobKind.CHECK_HOSTS, jobs.get(0).kind());
        assertEquals(List.of("a.example.com", "b.example.com"), jobs.get(0).hosts());
        assertEquals(null, jobs.get(0).domain());
        assertEquals("2 hosts", jobs.get(0).label());
    }

    @Test
    void extensionTrafficIsIgnored() {
        watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.EXTENSIONS));
        watcher().drainNow(T0);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void offCollectsAndQueuesNothing() {
        enabled.set(false);
        HttpRequestToBeSent r = request("a.example.com", true, ToolType.PROXY);
        assertSame(sent, watcher().handleHttpRequestToBeSent(r));
        enabled.set(true);
        watcher().drainNow(T0);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void turningOffDropsWhatWasCollected() {
        watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY));
        enabled.set(false);
        watcher().drainNow(T0);
        enabled.set(true);
        watcher().drainNow(T0.plusSeconds(60));
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void nothingNewQueuesNothing() {
        watcher().drainNow(T0);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void aFailedDrainIsLoggedAndTheWatcherGoesOn() {
        batcher = new NewHostBatcher(Duration.ofSeconds(60), Duration.ofHours(24), h -> {
            throw new IllegalStateException("store broke");
        }, () -> "scan.hirdman.pro");
        watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY));
        watcher().drainSafely(T0);
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: traffic check failed: "), errors.get(0));
    }

    @Test
    void startAndCloseRunTheTimer() {
        watcher().start();
        assertTrue(watcher().running());
        watcher().close();
        assertTrue(!watcher().running());
    }

    @Test
    void intruderAndScannerResponsesAreNotLookedAt() {
        watcher().handleHttpResponseReceived(response(ToolType.INTRUDER));
        watcher().handleHttpResponseReceived(response(ToolType.SCANNER));
        assertEquals(List.of(), looked);
        HttpResponseReceived repeater = response(ToolType.REPEATER);
        watcher().handleHttpResponseReceived(repeater);
        assertEquals(List.of(repeater), looked);
    }

    @Test
    void sequencerResponsesAreNotLookedAt() {
        watcher().handleHttpResponseReceived(response(ToolType.SEQUENCER));
        assertEquals(List.of(), looked);
    }

    @Test
    void newHostsWaitWhileTheLastTrafficCheckIsUnfinished() throws Exception {
        hold = new java.util.concurrent.CountDownLatch(1);
        try {
            watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY));
            watcher().drainNow(T0);
            watcher().handleHttpRequestToBeSent(request("b.example.com", true, ToolType.PROXY));
            watcher().drainNow(T0.plusSeconds(60));
            assertEquals(1, queue.jobs().size(), "a check waiting for the hourly limit does not pile up others");
        } finally {
            hold.countDown();
        }
        Job first = queue.jobs().get(0);
        for (int i = 0; i < 500 && !first.state().finished(); i++) {
            Thread.sleep(10);
        }
        watcher().drainNow(T0.plusSeconds(120));
        // The first check failed (no server here), so its host goes out again with the new one.
        assertEquals(List.of(List.of("a.example.com"), List.of("b.example.com", "a.example.com")),
                queue.jobs().stream().map(Job::hosts).toList());
    }

    @Test
    void intruderScannerAndSequencerRequestsAreNotNoted() {
        java.util.concurrent.atomic.AtomicInteger asked = new java.util.concurrent.atomic.AtomicInteger();
        for (ToolType t : List.of(ToolType.INTRUDER, ToolType.SCANNER, ToolType.SEQUENCER)) {
            watcher().handleHttpRequestToBeSent(request("a.example.com", true, t, asked));
        }
        watcher().drainNow(T0);
        assertTrue(queue.jobs().isEmpty());
        assertEquals(0, asked.get());
    }

    @Test
    void aHostNotedOnceIsNotAskedAboutScopeAgainUntilTheNextDrain() {
        java.util.concurrent.atomic.AtomicInteger asked = new java.util.concurrent.atomic.AtomicInteger();
        for (int i = 0; i < 5; i++) {
            watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY, asked));
        }
        assertEquals(1, asked.get());
        watcher().drainNow(T0);
        watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY, asked));
        assertEquals(2, asked.get());
    }

    @Test
    void outOfScopeRequestsAreAskedEachTime() {
        // Scope can depend on the path, so a host seen out of scope once may be in scope on its next request.
        java.util.concurrent.atomic.AtomicInteger asked = new java.util.concurrent.atomic.AtomicInteger();
        watcher().handleHttpRequestToBeSent(request("a.example.com", false, ToolType.PROXY, asked));
        watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY, asked));
        assertEquals(2, asked.get());
        watcher().drainNow(T0);
        assertEquals(List.of(List.of("a.example.com")), queue.jobs().stream().map(Job::hosts).toList());
    }

    @Test
    void aCancelledTrafficCheckIsNotSentAgainUntilItsHostsShowUp() throws Exception {
        hold = new java.util.concurrent.CountDownLatch(1);
        Job first;
        try {
            watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY));
            watcher().drainNow(T0);
            first = queue.jobs().get(0);
            queue.cancel(first);
        } finally {
            hold.countDown();
        }
        watcher().drainNow(T0.plusSeconds(60));
        assertEquals(1, queue.jobs().size());
        watcher().handleHttpRequestToBeSent(request("a.example.com", true, ToolType.PROXY));
        watcher().drainNow(T0.plusSeconds(120));
        assertEquals(List.of(List.of("a.example.com"), List.of("a.example.com")), queue.jobs().stream().map(Job::hosts).toList());
    }
}
