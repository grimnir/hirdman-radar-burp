package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.event.KeyEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobRunner;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.Sleeper;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.Risk;

class ScopeCheckButtonTest {

    final ResultStore store = new ResultStore();
    // An invalid server makes every queued job fail at once, so nothing reaches the network.
    final JobRunner runner = new JobRunner(() -> null, store, new MetaGate(), Sleeper.real(),
            () -> new JobRunner.RunOptions(null, "test", false, 5, true), e -> { }, e -> { });
    final JobQueue queue = new JobQueue(runner, () -> null, j -> { });
    final AtomicReference<Options> options = new AtomicReference<>(Options.defaults());
    final List<String> scopeHosts = new ArrayList<>();
    final AtomicInteger walks = new AtomicInteger();
    final AtomicInteger limitCalls = new AtomicInteger();
    final AtomicReference<Meta.Limits> limits = new AtomicReference<>();
    final TestLog log = new TestLog();
    final List<String> said = new ArrayList<>();
    final List<String> asked = new ArrayList<>();
    final AtomicReference<Boolean> agree = new AtomicReference<>(false);

    final ScopeCheckButton scope = new ScopeCheckButton(options::get, store, queue, this::walk, o -> {
        limitCalls.incrementAndGet();
        return limits.get();
    }, Runnable::run, log, said::add, q -> {
        asked.add(q);
        return agree.get();
    });

    List<String> walk() {
        walks.incrementAndGet();
        return List.copyOf(scopeHosts);
    }

    @AfterEach
    void tearDown() {
        queue.shutdown();
    }

    void click() throws Exception {
        scope.button.doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
    }

    @Test
    void theButtonHasAMnemonic() {
        assertEquals("Check in-scope hosts", scope.button.getText());
        assertEquals(KeyEvent.VK_I, scope.button.getMnemonic());
    }

    @Test
    void checkInScopeHostsAsksWithTheCountsThenQueues() throws Exception {
        scopeHosts.addAll(List.of("a.example.com", "b.example.com", "c.example.com"));
        store.apply("example.com", new Check(false, "b.example.com", 0, 0, 0, 0, 1, true, List.of()), Instant.now());
        // hosts_left is asked afresh: the tab's /meta answer may be hours old.
        limits.set(new Meta.Limits(50, 1.5, 300, 120));
        click();
        assertEquals(List.of("Check 2 in-scope hosts from the site map for leaks? 1 host checked in the last 24 h is skipped. "
                + "Your address can check 120 more hosts this hour."), asked);
        assertTrue(queue.jobs().isEmpty());
        assertTrue(scope.button.isEnabled());
        agree.set(true);
        click();
        assertEquals(List.of(JobKind.CHECK_HOSTS), queue.jobs().stream().map(Job::kind).toList());
        assertEquals(List.of("a.example.com", "c.example.com"), queue.jobs().get(0).hosts());
    }

    @Test
    void checkInScopeHostsSaysWhenThereIsNothingToSend() throws Exception {
        click();
        Options d = Options.defaults();
        options.set(new Options(d.serverUrl(), true, true, Risk.LOW, true, false, true, 5, false, true));
        click();
        assertEquals(List.of("No in-scope host names in the site map.", ServerLine.OFF_FOR_PROJECT.text()), said);
        assertEquals(List.of(), asked);
        assertEquals(1, walks.get());
        assertEquals(0, limitCalls.get());
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void aHostWhoseCheckFailedIsNotSkippedAsRecentlyChecked() throws Exception {
        scopeHosts.addAll(List.of("a.example.com", "b.example.com"));
        store.apply("example.com", new Check(false, "b.example.com", 0, 0, 0, 0, 0, false, List.of()), Instant.now());
        agree.set(true);
        click();
        assertTrue(asked.get(0).startsWith("Check 2 in-scope hosts from the site map for leaks?"), asked.toString());
        assertEquals(List.of("a.example.com", "b.example.com"), queue.jobs().get(0).hosts());
    }

    @Test
    void aSiteMapThatCannotBeReadIsLoggedAndSendsNothing() throws Exception {
        ScopeCheckButton broken = new ScopeCheckButton(options::get, store, queue, () -> {
            throw new IllegalStateException("boom");
        }, o -> null, Runnable::run, log, said::add, q -> {
            throw new AssertionError(q);
        });
        broken.button.doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(List.of("Hirdman Radar: could not read the site map"), log.errors);
        assertEquals(List.of(), said);
        assertTrue(broken.button.isEnabled());
        assertTrue(queue.jobs().isEmpty());
    }
}
