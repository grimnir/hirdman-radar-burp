package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

class ScopeIssuesTest {

    final List<HostResult> rows = List.of(new HostResult("a.example.com", "example.com", HostStatus.CHECKED, 1, 0, 0, 0, List.of(),
            Instant.EPOCH));
    final List<List<HostResult>> reported = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
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
        }, executor, errors::add);
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
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: issues after a scope change could not be created: "), errors.get(0));
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
