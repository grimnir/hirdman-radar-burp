package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.issues.IssueOptions;
import pro.hirdman.radar.issues.IssueSpec;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.Risk;

class BurpIssuesTest {

    // Issue names come from the finding kind.
    static final String STEALER = "Host found in infostealer logs";
    static final String WORK = "Work email addresses found in breaches";
    static final String P = "Hirdman Radar: ";

    final List<String> calls = new CopyOnWriteArrayList<>();
    final List<String> added = new ArrayList<>();
    final List<String> existing = new ArrayList<>();
    final List<AuditIssue> others = new ArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    String refused;
    boolean lookupFails;
    boolean inScope = true;
    IssueOptions options = new IssueOptions(true, false, Risk.LOW, null);

    BurpIssues issues() {
        Scope scope = fake(Scope.class, (m, a) -> {
            calls.add("scope " + a[0]);
            return inScope;
        });
        SiteMap siteMap = fake(SiteMap.class, (m, a) -> {
            if (m.equals("add")) {
                String name = ((AuditIssue) a[0]).name();
                if (name.equals(refused)) {
                    throw new IllegalStateException("Burp says no");
                }
                added.add(name);
                return null;
            }
            return Fakes.DEFAULT;
        });
        Logging logging = fake(Logging.class, (m, a) -> {
            errors.add(m + " " + a[0]);
            return null;
        });
        MontoyaApi api = fake(MontoyaApi.class, Map.of("scope", scope, "siteMap", siteMap, "logging", logging));
        return new BurpIssues(api, () -> options, () -> {
            calls.add("existing");
            if (lookupFails) {
                throw new IllegalStateException("lookup failed");
            }
            List<AuditIssue> all = new ArrayList<>(others);
            existing.forEach(n -> all.add(issue(n, "https://vpn.example.com/")));
            return all;
        }, spec -> issue(spec.name()));
    }

    static AuditIssue issue(String name) {
        return fake(AuditIssue.class, Map.of("name", name));
    }

    static AuditIssue issue(String name, String baseUrl) {
        return fake(AuditIssue.class, Map.of("name", name, "baseUrl", baseUrl));
    }

    static HostResult row(HostStatus status, String... names) {
        return row("vpn.example.com", status, names);
    }

    static HostResult row(String host, HostStatus status, String... names) {
        List<Finding> findings = List.of(names).stream()
                .map(n -> new Finding(n.equals(WORK) ? "work_accounts" : "stealer_logs", "high", "tentative", n, "<p>d</p>", "<p>b</p>", "<p>r</p>")).toList();
        return new HostResult(host, "example.com", status, 3, 0, 0, 0, findings, Instant.EPOCH);
    }

    @Test
    void reportsEachFindingOncePerSession() {
        BurpIssues b = issues();
        assertEquals(2, b.report(row(HostStatus.CHECKED, STEALER, WORK)));
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER, WORK)));
        assertEquals(List.of(P + STEALER, P + WORK), added);
        assertEquals("scope https://vpn.example.com/", calls.get(0));
        assertEquals("existing", calls.get(1));
    }

    @Test
    void creatingAgainRecreatesAnIssueDeletedInBurp() {
        BurpIssues b = issues();
        assertEquals(1, b.report(row(HostStatus.CHECKED, STEALER)));
        // Deleted in Burp: its list stays empty, and this session still remembers the issue.
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER)));
        assertEquals(1, b.reportAgain(List.of(row(HostStatus.CHECKED, STEALER))));
        assertEquals(List.of(P + STEALER, P + STEALER), added);
    }

    @Test
    void creatingAgainAsksBurpEachTimeAndSkipsWhatItHas() {
        BurpIssues b = issues();
        b.report(row(HostStatus.CHECKED, STEALER));
        existing.add(P + STEALER);
        calls.clear();
        assertEquals(0, b.reportAgain(List.of(row(HostStatus.CHECKED, STEALER), row("mail.example.com", HostStatus.CHECKED))));
        assertEquals(0, b.reportAgain(List.of(row(HostStatus.CHECKED, STEALER))));
        assertEquals(2, calls.stream().filter("existing"::equals).count());
        assertEquals(List.of(P + STEALER), added);
    }

    @Test
    void aHostWithEverythingCreatedIsNotLookedUpAgain() {
        BurpIssues b = issues();
        b.report(row(HostStatus.CHECKED, STEALER));
        calls.clear();
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER)));
        assertEquals(List.of("scope https://vpn.example.com/"), calls);
    }

    @Test
    void issuesAlreadyInBurpAreRememberedAndNotLookedUpAgain() {
        existing.add(P + STEALER);
        BurpIssues b = issues();
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER)));
        calls.clear();
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER)));
        assertEquals(List.of("scope https://vpn.example.com/"), calls);
    }

    @Test
    void reportAllCreatesWhatBecameDueAfterAScopeChange() {
        inScope = false;
        BurpIssues b = issues();
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER)));
        assertEquals(List.of(), added);
        inScope = true;
        assertEquals(1, b.reportAll(List.of(row(HostStatus.CHECKED, STEALER), row(HostStatus.CLEAN))));
        assertEquals(List.of(P + STEALER), added);
    }

    @Test
    void anIssueBurpRefusesIsLoggedAndTheRestStillCount() {
        refused = P + STEALER;
        BurpIssues b = issues();
        assertEquals(1, b.report(row(HostStatus.CHECKED, STEALER, WORK)));
        assertEquals(List.of(P + WORK), added);
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith("logToError Hirdman Radar: issue \"" + P + STEALER + "\" for vpn.example.com could not be created: "),
                errors.get(0));
        assertTrue(errors.get(0).contains("Burp says no"), errors.get(0));
        refused = null;
        assertEquals(1, b.report(row(HostStatus.CHECKED, STEALER, WORK)), "a refused issue is tried again");
    }

    @Test
    void aFailedLookupIsLoggedAndNothingIsAdded() {
        lookupFails = true;
        BurpIssues b = issues();
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER)));
        assertEquals(List.of(), added);
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith("logToError Hirdman Radar: issues for vpn.example.com could not be created: "),
                errors.get(0));
        assertTrue(errors.get(0).contains("lookup failed"), errors.get(0));
        // The next report looks again, so an issue Burp already has is not made twice.
        lookupFails = false;
        existing.add(P + STEALER);
        assertEquals(0, b.report(row(HostStatus.CHECKED, STEALER)));
        assertEquals(List.of(), added);
    }

    @Test
    void issueAlreadyInTheSiteMapIsSkipped() {
        existing.add(P + STEALER);
        assertEquals(1, issues().report(row(HostStatus.CHECKED, STEALER, WORK)));
        assertEquals(List.of(P + WORK), added);
    }

    @Test
    void outOfScopeHostIsSkipped() {
        inScope = false;
        assertEquals(0, issues().report(row(HostStatus.CHECKED, STEALER)));
        assertEquals(List.of(), added);
    }

    @Test
    void rowWithoutFindingsAsksBurpNothing() {
        BurpIssues b = issues();
        assertEquals(0, b.report(row(HostStatus.NOT_CHECKED)));
        assertEquals(0, b.report(row(HostStatus.CLEAN)));
        assertEquals(List.of(), calls);
    }

    @Test
    void specValuesMapToBurpEnums() {
        assertEquals(AuditIssueSeverity.HIGH, BurpIssues.severity(spec("high", "certain")));
        assertEquals(AuditIssueSeverity.MEDIUM, BurpIssues.severity(spec("medium", "firm")));
        assertEquals(AuditIssueSeverity.LOW, BurpIssues.severity(spec("low", "tentative")));
        assertEquals(AuditIssueSeverity.INFORMATION, BurpIssues.severity(spec("information", "tentative")));
        assertEquals(AuditIssueConfidence.CERTAIN, BurpIssues.confidence(spec("high", "certain")));
        assertEquals(AuditIssueConfidence.FIRM, BurpIssues.confidence(spec("high", "firm")));
        assertEquals(AuditIssueConfidence.TENTATIVE, BurpIssues.confidence(spec("high", "tentative")));
    }

    static IssueSpec spec(String severity, String confidence) {
        return new IssueSpec("n", "", "", "https://a.example.com/", severity, confidence, "");
    }

    @Test
    void burpIsAskedForItsIssuesOncePerSession() {
        // Burp's lookup walks every issue of the project, so it is done once, not once per host.
        others.add(issue(P + WORK, "https://VPN.example.com:443/"));
        others.add(issue(P + STEALER, "https://other.example.com/"));
        others.add(issue("Cleartext submission of password", "https://vpn.example.com/"));
        others.add(issue(P + STEALER, "not a url"));
        BurpIssues b = issues();
        assertEquals(1, b.report(row(HostStatus.CHECKED, STEALER, WORK)));
        assertEquals(List.of(P + STEALER), added);
        assertEquals(2, b.report(row("mail.example.com", HostStatus.CHECKED, STEALER, WORK)));
        assertEquals(0, b.report(row("other.example.com", HostStatus.CHECKED, STEALER)));
        assertEquals(1, calls.stream().filter("existing"::equals).count(), calls.toString());
    }
}
