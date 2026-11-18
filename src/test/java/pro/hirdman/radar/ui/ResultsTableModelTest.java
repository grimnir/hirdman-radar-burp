package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.LoginPage;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.Risk;

class ResultsTableModelTest {

    static final String D = "example.com";

    final ResultStore store = new ResultStore();

    static Finding finding(String severity) {
        return new Finding("stealer", severity, "tentative", "Leak " + severity, "", "", "");
    }

    void checked(String host, int stealer, int work, int personal, long email, long url, Finding... findings) {
        store.apply(D, new Check(false, host, work, personal, email, url, stealer, true, List.of(findings)), Instant.EPOCH);
    }

    void notChecked(String host) {
        store.apply(D, new Check(false, host, 0, 0, 0, 0, 0, false, List.of()), Instant.EPOCH);
    }

    ResultsTableModel model(Predicate<String> inScope) {
        ResultsTableModel m = new ResultsTableModel(store, inScope);
        m.setDomain(D);
        return m;
    }

    static List<String> hosts(ResultsTableModel m) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < m.getRowCount(); i++) {
            out.add((String) m.getValueAt(i, ResultsTableModel.HOST));
        }
        return out;
    }

    @Test
    void columnsAreTheSpecOnes() {
        ResultsTableModel m = model(h -> true);
        List<String> names = new ArrayList<>();
        for (int i = 0; i < m.getColumnCount(); i++) {
            names.add(m.getColumnName(i));
        }
        assertEquals(List.of("Host", "Risk", "Scope", "Infostealer", "Work", "Personal", "DB rec", "Latest breach", "Login page", "Status"), names);
    }

    @Test
    void sortsByRiskThenHost() {
        checked("c.example.com", 0, 0, 0, 0, 0);
        checked("d.example.com", 1, 0, 0, 0, 0, finding("high"));
        checked("a.example.com", 0, 0, 2, 0, 0, finding("medium"));
        checked("b.example.com", 4, 0, 0, 0, 0, finding("high"));
        ResultsTableModel m = model(h -> true);
        assertEquals(List.of("b.example.com", "d.example.com", "a.example.com", "c.example.com"), hosts(m));
        assertEquals(Risk.HIGH, m.getValueAt(0, ResultsTableModel.RISK));
        assertEquals(Risk.NONE, m.getValueAt(3, ResultsTableModel.RISK));
    }

    @Test
    void notCheckedShowsBlankCounts() {
        notChecked("old.example.com");
        store.found(D, List.of("new.example.com"));
        checked("vpn.example.com", 12, 3, 40, 5, 2, finding("high"));
        ResultsTableModel m = model(h -> true);
        assertEquals(List.of("vpn.example.com", "new.example.com", "old.example.com"), hosts(m));
        for (int col = ResultsTableModel.STEALER; col <= ResultsTableModel.DB; col++) {
            assertEquals("", m.getValueAt(1, col));
            assertEquals("", m.getValueAt(2, col));
        }
        assertEquals("Not checked yet", m.getValueAt(1, ResultsTableModel.STATUS));
        assertEquals("Check failed", m.getValueAt(2, ResultsTableModel.STATUS));
        assertEquals(12, m.getValueAt(0, ResultsTableModel.STEALER));
        assertEquals(3, m.getValueAt(0, ResultsTableModel.WORK));
        assertEquals(40, m.getValueAt(0, ResultsTableModel.PERSONAL));
        assertEquals(7L, m.getValueAt(0, ResultsTableModel.DB));
        assertEquals("Checked (leaks found)", m.getValueAt(0, ResultsTableModel.STATUS));
    }

    @Test
    void filtersWork() {
        checked("a.example.com", 1, 0, 0, 0, 0, finding("high"));
        checked("b.example.com", 0, 0, 0, 0, 0);
        notChecked("c.example.com");
        ResultsTableModel m = model(h -> h.equals("a.example.com") || h.equals("c.example.com"));
        assertEquals(ResultsFilter.ALL, m.filter());
        assertEquals(3, m.getRowCount());
        assertEquals("in", m.getValueAt(0, ResultsTableModel.SCOPE));
        assertEquals("out", m.getValueAt(1, ResultsTableModel.SCOPE));
        m.setFilter(ResultsFilter.WITH_LEAKS);
        assertEquals(List.of("a.example.com"), hosts(m));
        m.setFilter(ResultsFilter.FAILED);
        assertEquals(List.of("c.example.com"), hosts(m));
        m.setFilter(ResultsFilter.NOT_CHECKED_YET);
        assertEquals(List.of(), hosts(m));
        store.found(D, List.of("d.example.com"));
        m.refresh();
        assertEquals(List.of("d.example.com"), hosts(m));
        m.setFilter(ResultsFilter.IN_SCOPE);
        assertEquals(List.of("a.example.com", "c.example.com"), hosts(m));
        m.setFilter(ResultsFilter.ALL);
        assertEquals(4, m.getRowCount());
    }

    @Test
    void filterLabelsAreTheSpecOnes() {
        assertEquals(List.of("All", "With leaks", "Not checked yet", "Check failed", "In scope"),
                List.of(ResultsFilter.values()).stream().map(ResultsFilter::toString).toList());
    }

    @Test
    void summaryCountsLeaksAndUnchecked() {
        checked("a.example.com", 1, 0, 0, 0, 0, finding("high"));
        checked("b.example.com", 0, 0, 0, 0, 0);
        notChecked("c.example.com");
        ResultsTableModel m = model(h -> true);
        assertEquals("3 hosts, 1 with leaks, 1 failed", m.summary());
        m.setFilter(ResultsFilter.WITH_LEAKS);
        assertEquals("3 hosts, 1 with leaks, 1 failed", m.summary());
        store.found(D, List.of("d.example.com", "e.example.com"));
        m.refresh();
        assertEquals("5 hosts, 1 with leaks, 2 not checked yet, 1 failed", m.summary());
    }

    @Test
    void theStatusTipSaysWhenTheHostWasChecked() {
        Instant at = Instant.parse("2026-11-18T11:05:00Z");
        store.apply(D, new Check(false, "a.example.com", 0, 0, 0, 0, 1, true, List.of(finding("high"))), at);
        store.apply(D, new Check(false, "b.example.com", 0, 0, 0, 0, 0, true, List.of()), at);
        store.apply(D, new Check(false, "c.example.com", 0, 0, 0, 0, 0, false, List.of()), at);
        store.found(D, List.of("d.example.com"));
        ResultsTableModel m = model(h -> true);
        Map<String, String> tips = new HashMap<>();
        for (int row = 0; row < m.getRowCount(); row++) {
            tips.put(m.rowAt(row).host(), m.statusText(row));
        }
        assertEquals("Checked 2026-11-18 11:05 UTC", tips.get("a.example.com"));
        assertEquals("Checked 2026-11-18 11:05 UTC", tips.get("b.example.com"));
        assertEquals("Last tried 2026-11-18 11:05 UTC", tips.get("c.example.com"));
        assertEquals(null, tips.get("d.example.com"));
        assertTrue(tips.containsKey("d.example.com"));
    }

    @Test
    void summaryOmitsZeroNotCheckedAndSaysOneHost() {
        checked("b.example.com", 0, 0, 0, 0, 0);
        assertEquals("1 host, 0 with leaks", model(h -> true).summary());
        assertEquals("", new ResultsTableModel(store, h -> true).summary());
    }

    @Test
    void showsOnlyTheChosenDomainAndFollowsTheStore() {
        checked("a.example.com", 0, 0, 0, 0, 0);
        store.apply("other.org", new Check(false, "x.other.org", 0, 0, 0, 0, 0, true, List.of()), Instant.EPOCH);
        ResultsTableModel m = model(h -> true);
        assertEquals(List.of("a.example.com"), hosts(m));
        m.setDomain("other.org");
        assertEquals(List.of("x.other.org"), hosts(m));
        assertEquals("other.org", m.domain());
        store.apply("other.org", new Check(false, "y.other.org", 0, 0, 0, 0, 0, true, List.of()), Instant.EPOCH);
        assertEquals(1, m.getRowCount());
        m.refresh();
        assertEquals(2, m.getRowCount());
    }

    @Test
    void rowsGiveHostsCsvAndNotChecked() {
        checked("vpn.example.com", 12, 3, 40, 5, 2, finding("high"));
        notChecked("old.example.com");
        notChecked("old2.example.com");
        ResultsTableModel m = model(h -> !h.startsWith("old2"));
        assertEquals("vpn.example.com", m.rowAt(0).host());
        assertEquals(List.of("old.example.com", "old2.example.com"), m.failed());
        assertEquals("Host,Risk,Scope,Infostealer,Work,Personal,DB rec,Latest breach,Login page,Status\n"
                + "vpn.example.com,High,in,12,3,40,7,,,Checked (leaks found)\n"
                + "old2.example.com,,out,,,,,,,Check failed\n", m.csv(new int[] {0, 2}));
        store.noteLogin("vpn.example.com", new LoginPage(LoginPage.Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login"));
        m.refresh();
        assertEquals("FortiGate SSL VPN", m.getValueAt(0, ResultsTableModel.LOGIN));
        assertEquals("", m.getValueAt(1, ResultsTableModel.LOGIN));
        assertEquals("High", m.text(0, ResultsTableModel.RISK));
        assertEquals("12", m.text(0, ResultsTableModel.STEALER));
    }

    @Test
    void scopeIsAskedOncePerHostUntilItIsForgotten() {
        checked("a.example.com", 0, 0, 0, 0, 0);
        checked("b.example.com", 0, 0, 0, 0, 0);
        java.util.Set<String> scope = new java.util.HashSet<>();
        int[] asked = {0};
        ResultsTableModel m = model(h -> {
            asked[0]++;
            return scope.contains(h);
        });
        assertEquals(2, asked[0]);
        m.refresh();
        m.refresh();
        assertEquals(2, asked[0]);
        scope.add("a.example.com");
        m.forgetScope();
        m.refresh();
        assertEquals(4, asked[0]);
        assertEquals("in", m.getValueAt(hosts(m).indexOf("a.example.com"), ResultsTableModel.SCOPE));
    }

    @Test
    void cellsAreReadOnly() {
        checked("a.example.com", 0, 0, 0, 0, 0);
        ResultsTableModel m = model(h -> true);
        for (int c = 0; c < m.getColumnCount(); c++) {
            assertTrue(!m.isCellEditable(0, c));
        }
    }

    @Test
    void latestBreachAndItsSourcesAreShown() {
        store.apply(D, new Check(false, "vpn.example.com", 3, 0, 0, 0, 1, true, List.of(finding("high")),
                List.of(new BreachSource("Stealer Logs", "2024-03", 12), new BreachSource("<html><img src=x>", "2012", 3),
                        new BreachSource("No date", null, 1))), Instant.EPOCH);
        checked("clean.example.com", 0, 0, 0, 0, 0);
        notChecked("old.example.com");
        ResultsTableModel m = model(h -> true);
        assertEquals("2024-03", m.getValueAt(0, ResultsTableModel.LATEST));
        assertEquals("", m.getValueAt(1, ResultsTableModel.LATEST));
        assertEquals("", m.getValueAt(2, ResultsTableModel.LATEST));
        // Never starts with <html>, so Swing shows it as text.
        assertEquals("Breach sources: Stealer Logs 12 (2024-03); <html><img src=x> 3 (2012); No date 1 (no date). Newer leaks may exist: not every record is dated.",
                m.sourcesText(0));
        assertEquals(null, m.sourcesText(1));
    }

    @Test
    void countsHostsWithLeaksOutOfScopeOverTheWholeDomain() {
        checked("a.example.com", 1, 0, 0, 0, 0, finding("high"));
        checked("b.example.com", 1, 0, 0, 0, 0, finding("high"));
        checked("c.example.com", 0, 0, 0, 0, 0);
        notChecked("d.example.com");
        ResultsTableModel m = model(h -> h.equals("a.example.com"));
        assertEquals(1, m.leaksOutOfScope());
        m.setFilter(ResultsFilter.IN_SCOPE);
        assertEquals(1, m.leaksOutOfScope());
        assertTrue(m.inScope("a.example.com"));
        assertTrue(!m.inScope("b.example.com"));
    }
}
