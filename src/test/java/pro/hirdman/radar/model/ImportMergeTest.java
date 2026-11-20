package pro.hirdman.radar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ImportMergeTest {

    static final Instant T1 = ResultStoreTest.T1;
    static final Instant T2 = ResultStoreTest.T2;

    static HostResult row(String host, int stealer, Instant at) {
        return new HostResult(host, "example.com", HostStatus.CHECKED, stealer, 0, 0, 0,
                List.of(ResultStoreTest.finding("stealer_logs", "high")), at);
    }

    final ResultStore store = new ResultStore();
    final List<Set<String>> heard = new ArrayList<>();
    final List<HostResult> checks = new ArrayList<>();

    ImportMergeTest() {
        store.addDomainListener(heard::add);
        store.addCheckListener(checks::add);
    }

    @Test
    void theNewerCheckOfEachHostWins() {
        store.apply("example.com", PreviousCheckTest.counts("a.example.com", 1, 0, 0, 0), T1);
        store.apply("example.com", PreviousCheckTest.counts("b.example.com", 1, 0, 0, 0), T2);
        store.apply("example.com", PreviousCheckTest.counts("c.example.com", 1, 0, 0, 0), T1);
        heard.clear();
        checks.clear();
        ResultStore.Merged m = store.merge(List.of(row("a.example.com", 9, T2), row("b.example.com", 9, T1),
                row("c.example.com", 9, T1), row("d.example.com", 9, T1)));
        assertEquals(new ResultStore.Merged(1, 1, 2, 0), m);
        assertEquals(9, store.host("a.example.com").orElseThrow().stealer(), "newer in the file");
        assertEquals(1, store.host("b.example.com").orElseThrow().stealer(), "newer in the project");
        assertEquals(1, store.host("c.example.com").orElseThrow().stealer(), "a tie keeps the project's row");
        assertEquals(9, store.host("d.example.com").orElseThrow().stealer(), "new host");
        assertEquals(List.of(Set.of("example.com")), heard, "one change for the tab and the project file");
        assertEquals(List.of(), checks, "an import is no check: no issues, no site map");
    }

    @Test
    void aHostNotCheckedYetNeverReplacesARow() {
        store.apply("example.com", PreviousCheckTest.counts("a.example.com", 1, 0, 0, 0), T1);
        HostResult found = new HostResult("a.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null);
        HostResult other = new HostResult("b.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null);
        assertEquals(new ResultStore.Merged(1, 0, 1, 0), store.merge(List.of(found, other)));
        assertEquals(HostStatus.CHECKED, store.host("a.example.com").orElseThrow().status());
        assertEquals(HostStatus.FOUND, store.host("b.example.com").orElseThrow().status());
    }

    @Test
    void theProjectsLoginPageStaysWhenItSaysMore() {
        store.found("example.com", List.of("a.example.com", "b.example.com"));
        store.noteLogin("a.example.com", ResultStoreTest.VPN);
        store.noteLogin("b.example.com", ResultStoreTest.FORM);
        store.merge(List.of(row("a.example.com", 2, T1).withLogin(ResultStoreTest.FORM),
                row("b.example.com", 2, T1).withLogin(ResultStoreTest.VPN)));
        assertEquals(ResultStoreTest.VPN, store.host("a.example.com").orElseThrow().login());
        assertEquals(ResultStoreTest.VPN, store.host("b.example.com").orElseThrow().login());
    }

    @Test
    void nothingChangedTellsNoOne() {
        store.apply("example.com", PreviousCheckTest.counts("a.example.com", 1, 0, 0, 0), T2);
        heard.clear();
        assertEquals(new ResultStore.Merged(0, 0, 1, 0), store.merge(List.of(row("a.example.com", 9, T1))));
        assertEquals(List.of(), heard);
    }

    @Test
    void newHostsStopAtTheProjectLimit() {
        store.apply("example.com", PreviousCheckTest.counts("a.example.com", 1, 0, 0, 0), T1);
        assertEquals(new ResultStore.Merged(1, 1, 0, 1), store.merge(List.of(row("b.example.com", 1, T1),
                row("c.example.com", 1, T1), row("a.example.com", 5, T2)), 2));
        assertEquals(List.of("a.example.com", "b.example.com"), store.all().stream().map(HostResult::host).toList());
    }
}
