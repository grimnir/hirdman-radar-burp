package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.CopyOnWriteArrayList;
import static org.junit.jupiter.api.Assertions.assertSame;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

class ScopeIssuesTest {

    final List<HostResult> rows = List.of(new HostResult("a.example.com", "example.com", HostStatus.CHECKED, 1, 0, 0, 0, List.of(),
            Instant.EPOCH));
    final List<List<HostResult>> reported = new ArrayList<>();
    final List<String> errors = new ArrayList<>();

    final List<Throwable> causes = new CopyOnWriteArrayList<>();

    /** Burp's logToError(String, Throwable): the message and its cause apart. */
    void error(String message, Throwable cause) {
        errors.add(message);
        causes.add(cause);
    }
    final List<Runnable> queued = new ArrayList<>();
    boolean auto = true;
    RuntimeException failure;

    ScopeIssues scopeIssues(Executor executor) {
        return new ScopeIssues(() -> rows, () -> auto, all -> {
            if (failure != null) {
                throw failure;
            }
            reported.add(all);
            return all.size();
        }, executor, this::error, (task, delay) -> {
            delays.add(delay);
            task.run();
        });
    }

    final List<java.time.Duration> delays = new ArrayList<>();

    @Test
    void aBurstOfChangesWaitsASecondAndMakesOnePass() {
        List<Runnable> waiting = new ArrayList<>();
        ScopeIssues s = new ScopeIssues(() -> rows, () -> auto, all -> {
            reported.add(all);
            return all.size();
        }, Runnable::run, this::error, (task, delay) -> {
            delays.add(delay);
            waiting.add(task);
        });
        for (int i = 0; i < 20; i++) {
            s.scopeChanged(null);
        }
        assertEquals(List.of(java.time.Duration.ofSeconds(1)), delays);
        assertEquals(List.of(), reported);
        waiting.get(0).run();
        assertEquals(List.of(rows), reported);
        s.scopeChanged(null);
        assertEquals(2, waiting.size());
    }

    @Test
    void aScopeChangeOffersEveryRowAgain() {
        scopeIssues(Runnable::run).scopeChanged(null);
        assertEquals(List.of(rows), reported);
    }

    @Test
    void nothingWhenIssuesAreNotCreatedAutomatically() {
        auto = false;
        scopeIssues(Runnable::run).scopeChanged(null);
        assertEquals(List.of(), reported);
    }

    @Test
    void changesWhileAPassWaitsMakeOnePass() {
        ScopeIssues s = scopeIssues(queued::add);
        s.scopeChanged(null);
        s.scopeChanged(null);
        s.scopeChanged(null);
        assertEquals(1, queued.size());
        queued.remove(0).run();
        assertEquals(1, reported.size());
        s.scopeChanged(null);
        assertEquals(1, queued.size());
    }

    @Test
    void aFailedPassIsLoggedAndTheNextChangeRunsAgain() {
        failure = new IllegalStateException("site map busy");
        ScopeIssues s = scopeIssues(Runnable::run);
        s.scopeChanged(null);
        assertEquals(List.of("Hirdman Radar: issues after a scope change could not be created"), errors);
        assertSame(failure, causes.get(0));
        failure = null;
        s.scopeChanged(null);
        assertEquals(List.of(rows), reported);
    }

    @Test
    void aRefusedPassDoesNotBlockLaterOnes() {
        boolean[] refuse = {true};
        ScopeIssues s = scopeIssues(r -> {
            if (refuse[0]) {
                throw new RejectedExecutionException("unloading");
            }
            r.run();
        });
        s.scopeChanged(null);
        refuse[0] = false;
        s.scopeChanged(null);
        assertEquals(List.of(rows), reported);
    }
}
