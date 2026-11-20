package pro.hirdman.radar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;

class ResultStoreTest {

    static final Instant T1 = Instant.parse("2026-11-17T10:00:00Z");
    static final Instant T2 = Instant.parse("2026-11-17T11:00:00Z");

    static Finding finding(String kind, String severity) {
        return new Finding(kind, severity, "tentative", "Name " + kind, "<p>d</p>", "<p>b</p>", "<p>r</p>");
    }

    static Check check(String host, Boolean checked, int stealer, Finding... findings) {
        return new Check(false, host, 3, 40, 5, 2, stealer, checked, List.of(findings));
    }

    static final LoginPage FORM = new LoginPage(LoginPage.Kind.PASSWORD_FORM, "Password form", "/login");
    static final LoginPage VPN = new LoginPage(LoginPage.Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login");

    @Test
    void theServersCheckTimeAndReplayAreKept() {
        ResultStore s = new ResultStore();
        Check replayed = new Check(false, "vpn.example.com", 0, 0, 0, 0, 0, true, List.of(), List.of(), "2026-11-17T08:30:00Z", true);
        HostResult r = s.apply("example.com", replayed, T2).orElseThrow();
        assertEquals(Instant.parse("2026-11-17T08:30:00Z"), r.checkedAt());
        assertTrue(r.replayed());
        s.noteLogin("vpn.example.com", FORM);
        assertTrue(s.host("vpn.example.com").orElseThrow().replayed());
        HostResult fresh = s.apply("example.com", check("vpn.example.com", true, 0), T2).orElseThrow();
        assertEquals(T2, fresh.checkedAt());
        assertFalse(fresh.replayed());
    }

    @Test
    void aLoginPageIsNotedOnKnownHostsAndOnlyImproves() {
        ResultStore s = new ResultStore();
        AtomicInteger changes = new AtomicInteger();
        List<HostResult> noted = new java.util.ArrayList<>();
        s.addListener(changes::incrementAndGet);
        s.addLoginListener(noted::add);
        assertFalse(s.noteLogin("vpn.example.com", FORM));
        s.found("example.com", List.of("vpn.example.com"));
        assertTrue(s.noteLogin("VPN.example.com", FORM));
        assertFalse(s.noteLogin("vpn.example.com", FORM));
        assertTrue(s.noteLogin("vpn.example.com", VPN));
        assertFalse(s.noteLogin("vpn.example.com", FORM));
        assertEquals(VPN, s.host("vpn.example.com").orElseThrow().login());
        assertEquals(List.of(FORM, VPN), noted.stream().map(HostResult::login).toList());
        assertEquals(3, changes.get());
        s.apply("example.com", check("vpn.example.com", true, 1, finding("stealer", "high")), T1);
        assertEquals(VPN, s.host("vpn.example.com").orElseThrow().login(), "a new check keeps the login page");
    }

    @Test
    void negativeCountsBecomeZeroAndHugeSumsStopAtTheTop() {
        ResultStore s = new ResultStore();
        HostResult neg = s.apply("example.com", new Check(false, "a.example.com", -3, -4, -5, -6, -7, true,
                List.of(finding("stealer", "high"))), T1).orElseThrow();
        assertEquals(List.of(0, 0, 0), List.of(neg.stealer(), neg.work(), neg.personal()));
        assertEquals(0, neg.dbRecords());
        HostResult huge = s.apply("example.com", new Check(false, "b.example.com", 1, 1, Long.MAX_VALUE, Long.MAX_VALUE, 1, true,
                List.of(finding("stealer", "high"))), T1).orElseThrow();
        assertEquals(Long.MAX_VALUE, huge.dbRecords());
    }

    @Test
    void domainListenersHearWhichDomainsChanged() {
        ResultStore s = new ResultStore();
        List<java.util.Set<String>> heard = new java.util.ArrayList<>();
        s.addDomainListener(heard::add);
        s.found("example.com", List.of("a.example.com"));
        s.apply("other.org", check("x.other.org", true, 0), T1);
        s.noteLogin("a.example.com", FORM);
        s.remove(List.of("a.example.com", "x.other.org"));
        s.remove(List.of("gone.example.com"));
        assertEquals(List.of(java.util.Set.of("example.com"), java.util.Set.of("other.org"), java.util.Set.of("example.com"),
                java.util.Set.of("example.com", "other.org")), heard);
    }

    @Test
    void peekReadsARowWithoutTheLock() throws Exception {
        ResultStore s = new ResultStore();
        s.found("example.com", List.of("vpn.example.com"));
        java.util.concurrent.ExecutorService other = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            synchronized (s) {
                assertEquals("vpn.example.com", other.submit(() -> s.peek("VPN.Example.COM").orElseThrow().host())
                        .get(2, java.util.concurrent.TimeUnit.SECONDS));
            }
        } finally {
            other.shutdownNow();
        }
        assertTrue(s.peek("vpn.example.com.").isPresent());
        assertTrue(s.peek("other.example.com").isEmpty());
        assertTrue(s.peek(null).isEmpty());
        s.remove(List.of("vpn.example.com"));
        assertTrue(s.peek("vpn.example.com").isEmpty());
    }

    @Test
    void checkedHostKeepsCountsAndFindings() {
        ResultStore s = new ResultStore();
        HostResult r = s.apply("example.com", check("vpn.example.com", true, 12, finding("stealer_logs", "high")), T1).orElseThrow();
        assertEquals(new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 12, 3, 40, 7,
                List.of(finding("stealer_logs", "high")), T1).withPrevious(HostResult.Previous.FIRST), r);
        assertEquals(Risk.HIGH, r.risk());
        assertTrue(r.hasLeaks());
        assertEquals(List.of(r), s.domain("example.com"));
        assertEquals(r, s.host("VPN.example.com").orElseThrow());
    }

    @Test
    void checkListenersGetTheNewRow() {
        ResultStore s = new ResultStore();
        List<HostResult> rows = new java.util.ArrayList<>();
        s.addCheckListener(rows::add);
        HostResult r = s.apply("example.com", check("vpn.example.com", true, 1, finding("stealer_logs", "high")), T1).orElseThrow();
        s.apply("example.com", check("_bad.example.com", true, 1), T1);
        assertEquals(List.of(r), rows);
    }

    @Test
    void foundListenersGetOnlyNewHosts() {
        ResultStore s = new ResultStore();
        List<List<String>> found = new java.util.ArrayList<>();
        s.addFoundListener(found::add);
        s.apply("example.com", check("a.example.com", true, 0), T1);
        s.found("example.com", List.of("a.example.com", "B.example.com", "10.0.0.1"));
        s.found("example.com", List.of("b.example.com"));
        assertEquals(List.of(List.of("b.example.com")), found);
    }

    @Test
    void notCheckedNeverClean() {
        ResultStore s = new ResultStore();
        HostResult r = s.apply("example.com", check("a.example.com", null, 9, finding("breached_db_records", "low")), T1)
                .orElseThrow();
        assertEquals(HostStatus.NOT_CHECKED, r.status());
        assertTrue(r.findings().isEmpty());
        assertFalse(r.hasLeaks());
        assertEquals(0, r.stealer());
        assertEquals(0, r.dbRecords());
        assertEquals(Risk.NONE, r.risk());
        assertEquals("Check failed", r.status().label());
    }

    @Test
    void checkedWithoutFindingsIsClean() {
        ResultStore s = new ResultStore();
        HostResult r = s.apply("example.com", check("a.example.com", true, 0), T1).orElseThrow();
        assertEquals(HostStatus.CLEAN, r.status());
        assertEquals("Checked (nothing found)", r.status().label());
        assertFalse(r.hasLeaks());
    }

    @Test
    void riskIsHighestSeverity() {
        assertEquals(Risk.MEDIUM, Risk.of(List.of(finding("personal_accounts", "medium"), finding("breached_db_records", "low"))));
        assertEquals("Medium", Risk.MEDIUM.label());
        assertEquals(Risk.HIGH, Risk.of(List.of(finding("x", "low"), finding("y", "HIGH"))));
        assertEquals(Risk.NONE, Risk.of(List.of(finding("x", "info"))));
        assertEquals("", Risk.NONE.label());
    }

    @Test
    void recheckUpdatesRowInPlace() {
        ResultStore s = new ResultStore();
        s.apply("example.com", check("vpn.example.com", true, 12, finding("stealer_logs", "high")), T1);
        s.apply("other.org", check("vpn.example.com", true, 0), T2);
        assertEquals(List.of("example.com"), s.domains());
        List<HostResult> rows = s.domain("example.com");
        assertEquals(1, rows.size());
        assertEquals(HostStatus.CLEAN, rows.get(0).status());
        assertEquals(T2, rows.get(0).checkedAt());
        assertTrue(s.domain("other.org").isEmpty());
    }

    @Test
    void foundDoesNotDowngradeChecked() {
        ResultStore s = new ResultStore();
        s.apply("example.com", check("vpn.example.com", true, 12, finding("stealer_logs", "high")), T1);
        s.found("example.com", List.of("vpn.example.com", "Blog.Example.com"));
        assertEquals(HostStatus.CHECKED, s.host("vpn.example.com").orElseThrow().status());
        HostResult blog = s.host("blog.example.com").orElseThrow();
        assertEquals(HostStatus.FOUND, blog.status());
        assertEquals("Not checked yet", blog.status().label());
        assertEquals(null, blog.checkedAt());
        assertEquals(List.of("vpn.example.com", "blog.example.com"), s.domain("example.com").stream().map(HostResult::host).toList());
    }

    @Test
    void badHostNeverEntersStore() {
        ResultStore s = new ResultStore();
        assertTrue(s.apply("example.com", check("<x>.example.com", true, 1), T1).isEmpty());
        s.found("example.com", List.of("a b.example.com", "10.0.0.1"));
        s.found("<b>", List.of("ok.example.com"));
        assertTrue(s.all().isEmpty());
        assertTrue(s.domains().isEmpty());
    }

    @Test
    void removeDropsRows() {
        ResultStore s = new ResultStore();
        s.found("example.com", List.of("a.example.com", "b.example.com"));
        s.remove(List.of("A.example.com"));
        assertEquals(List.of("b.example.com"), s.all().stream().map(HostResult::host).toList());
        s.remove(List.of("b.example.com"));
        assertTrue(s.domains().isEmpty());
    }

    @Test
    void listenersHearEveryChange() {
        ResultStore s = new ResultStore();
        AtomicInteger calls = new AtomicInteger();
        s.addListener(calls::incrementAndGet);
        s.found("example.com", List.of("a.example.com"));
        s.apply("example.com", check("a.example.com", true, 0), T1);
        s.remove(List.of("a.example.com"));
        assertEquals(3, calls.get());
        s.found("example.com", List.of("bad host"));
        assertEquals(3, calls.get());
    }

    static BreachSource src(String name, String date, int count) {
        return new BreachSource(name, date, count);
    }

    @Test
    void checkKeepsBreachSourcesAndTheLatestBreach() {
        ResultStore s = new ResultStore();
        Check c = new Check(false, "vpn.example.com", 3, 40, 5, 2, 12, true, List.of(finding("stealer_logs", "high")),
                List.of(src("A", "2012", 3), src("B", "2024-03-15", 9), src("C", null, 1), src("D", "2021-06", 2)));
        HostResult r = s.apply("example.com", c, T1).orElseThrow();
        assertEquals(4, r.sources().size());
        assertEquals("2024-03-15", r.latestBreach());
        assertEquals(null, s.apply("example.com", check("a.example.com", true, 0), T1).orElseThrow().latestBreach());
    }

    @Test
    void sourcesWithoutANameAreDroppedAndTenAreKept() {
        List<BreachSource> many = new java.util.ArrayList<>();
        many.add(null);
        many.add(src(null, "2020", 1));
        many.add(src("", "2020", 1));
        for (int i = 0; i < 15; i++) {
            many.add(src("S" + i, null, i));
        }
        HostResult r = new HostResult("a.example.com", "example.com", HostStatus.CHECKED, 0, 0, 0, 0, List.of(), T1, many);
        assertEquals(10, r.sources().size());
        assertEquals("S0", r.sources().get(0).name());
    }

    @Test
    void lastCheckedIsTheTimeOfASuccessfulCheckOnly() {
        ResultStore s = new ResultStore();
        s.apply("example.com", check("a.example.com", true, 0), T1);
        s.apply("example.com", check("b.example.com", null, 0), T1);
        s.found("example.com", java.util.List.of("c.example.com"));
        assertEquals(java.util.Optional.of(T1), s.lastChecked("A.example.com"));
        assertEquals(java.util.Optional.empty(), s.lastChecked("b.example.com"));
        assertEquals(java.util.Optional.empty(), s.lastChecked("c.example.com"));
        assertEquals(java.util.Optional.empty(), s.lastChecked("d.example.com"));
    }

    @Test
    void domainListsItsRowsInStoreOrderWhateverWasAddedOrRemoved() {
        ResultStore s = new ResultStore();
        java.util.Random rnd = new java.util.Random(7);
        List<String> domains = List.of("a.com", "b.org", "c.net");
        for (int step = 0; step < 2000; step++) {
            String d = domains.get(rnd.nextInt(3));
            String h = "h" + rnd.nextInt(40) + "." + d;
            switch (rnd.nextInt(4)) {
                case 0 -> s.found(d, List.of(h, "x" + rnd.nextInt(5) + "." + d));
                case 1 -> s.apply(d, check(h, true, rnd.nextInt(3)), T1);
                case 2 -> s.remove(List.of(h, "X" + rnd.nextInt(5) + "." + d));
                default -> s.apply(domains.get(rnd.nextInt(3)), check(h, true, 0), T2);
            }
            for (String x : domains) {
                assertEquals(s.all().stream().filter(r -> r.domain().equals(x)).toList(), s.domain(x), "step " + step);
            }
        }
        assertEquals(List.of(), s.domain("none.example"));
        assertEquals(List.of(), s.domain(null));
    }

    @Test
    void aSavedHostListedTwiceKeepsItsLastDomain() {
        String json = """
                {"v":1,"hosts":[
                  {"host":"a.example.com","domain":"example.com","status":"CLEAN"},
                  {"host":"b.example.com","domain":"example.com","status":"CLEAN"},
                  {"host":"x.a.example.com","domain":"a.example.com","status":"CLEAN"},
                  {"host":"a.example.com","domain":"a.example.com","status":"CLEAN"}
                ]}
                """;
        ResultStore s = ResultsJson.read(json, e -> { });
        assertEquals(List.of("b.example.com"), s.domain("example.com").stream().map(HostResult::host).toList());
        assertEquals(List.of("x.a.example.com", "a.example.com"), s.domain("a.example.com").stream().map(HostResult::host).toList());
        assertEquals(s.all().stream().filter(r -> r.domain().equals("a.example.com")).toList(), s.domain("a.example.com"));
    }
}
