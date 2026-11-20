package pro.hirdman.radar.issues;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.LoginPage;
import pro.hirdman.radar.model.Risk;

class IssuePlannerTest {

    static final IssueOptions DEFAULTS = new IssueOptions(true, false, Risk.LOW, null);
    static final String STEALER = "Infostealer records linked to host";
    static final String WORK = "Work accounts in leaks";
    /** Issue names say where they came from, in Burp and in its reports. */
    static final String P = "Hirdman Radar: ";

    static Finding f(String name, String severity) {
        return new Finding("stealer", severity, "tentative", name, "<p>Found <b>3</b> records.</p>", "<p>Why.</p>", "<p>Fix.</p>");
    }

    static final Instant CHECKED_AT = Instant.parse("2026-11-17T20:15:00Z");
    /** The plugin's own line after the server detail. */
    static final String CHECKED = "<p>Checked by Hirdman Radar on 2026-11-17 (UTC).</p>";

    static HostResult row(HostStatus status, Finding... findings) {
        return new HostResult("vpn.example.com", "example.com", status, 3, 2, 0, 0, List.of(findings), CHECKED_AT);
    }

    static List<IssueSpec> plan(HostResult r) {
        return IssuePlanner.plan(r, true, DEFAULTS, Set.of());
    }

    static final String LOGIN = "Login page on a host with leaked records";

    @Test
    void aLoginPageOnAHostWithLeaksGetsItsOwnIssue() {
        LoginPage page = new LoginPage(LoginPage.Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/<b>login");
        HostResult r = row(HostStatus.CHECKED, f(STEALER, "high")).withLogin(page);
        List<IssueSpec> specs = plan(r);
        assertEquals(2, specs.size());
        assertEquals(new IssueSpec(P + LOGIN,
                "<p>Burp traffic shows what looks like a login page on this host: <b>FortiGate SSL VPN</b> at "
                        + "<b>/remote/&lt;b&gt;login</b>. The leak archive has records for this host: 3 in infostealer logs, "
                        + "2 work accounts, 0 personal accounts, 0 database records.</p>"
                        + "<p>Leaked passwords are often tried on login pages like this one. Hirdman Radar counts records only and "
                        + "did not check whether any password works here.</p>" + CHECKED,
                "<p>Check that this login asks for a second factor and is open only to those who need it. A full HIRDMAN review "
                        + "shows which accounts the records belong to and whether their passwords still work.</p>",
                "https://vpn.example.com/", "low", "tentative", ""), specs.get(1));
        assertEquals(1, IssuePlanner.plan(r, true, new IssueOptions(true, false, Risk.MEDIUM, null), Set.of()).size());
        assertEquals(1, IssuePlanner.plan(r, true, DEFAULTS, Set.of(IssueSpec.key(P + LOGIN, "https://vpn.example.com/"))).size());
        assertEquals(List.of(P + LOGIN), plan(row(HostStatus.CHECKED, f(STEALER, "low")).withLogin(page)).stream()
                .map(IssueSpec::name).filter(n -> n.endsWith(LOGIN)).toList());
        assertTrue(plan(row(HostStatus.CLEAN).withLogin(page)).isEmpty());
    }

    @Test
    void checkedHostGetsOneIssuePerFinding() {
        List<IssueSpec> specs = plan(row(HostStatus.CHECKED, f(STEALER, "high"), f(WORK, "medium")));
        assertEquals(2, specs.size());
        assertEquals(new IssueSpec(P + STEALER, "<p>Found <b>3</b> records.</p>" + CHECKED, "<p>Fix.</p>", "https://vpn.example.com/", "high",
                "tentative", "<p>Why.</p>"), specs.get(0));
        assertEquals(P + WORK, specs.get(1).name());
        assertEquals("medium", specs.get(1).severity());
        assertEquals(P + STEALER + "|https://vpn.example.com/", specs.get(0).key());
    }

    @Test
    void detailLinksToTheDomainOnTheRadarSite() {
        IssueOptions o = new IssueOptions(true, false, Risk.LOW, "https://scan.hirdman.pro");
        IssueSpec s = IssuePlanner.plan(row(HostStatus.CHECKED, f(STEALER, "high")), true, o, Set.of()).get(0);
        String url = "https://scan.hirdman.pro/?domain=example.com";
        assertEquals("<p>Found <b>3</b> records.</p><p>Checked by Hirdman Radar on 2026-11-17 (UTC). Latest scan of example.com"
                + " and its subdomains: <a href=\"" + url + "\">" + url + "</a>. Its counts can differ from this issue.</p>", s.detail());
        assertEquals(P + STEALER + "|https://vpn.example.com/", s.key());
    }

    @Test
    void noLinkWithoutASiteOrAValidDomain() {
        assertEquals("<p>Found <b>3</b> records.</p>" + CHECKED, plan(row(HostStatus.CHECKED, f(STEALER, "high"))).get(0).detail());
        IssueOptions o = new IssueOptions(true, false, Risk.LOW, "https://scan.hirdman.pro");
        HostResult odd = new HostResult("vpn.example.com", "<b>", HostStatus.CHECKED, 3, 2, 0, 0, List.of(f(STEALER, "high")),
                CHECKED_AT);
        assertEquals("<p>Found <b>3</b> records.</p>" + CHECKED, IssuePlanner.plan(odd, true, o, Set.of()).get(0).detail());
    }

    @Test
    void withoutACheckTimeOnlyTheLinkIsAdded() {
        HostResult undated = new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 3, 2, 0, 0,
                List.of(f(STEALER, "high")), null);
        assertEquals("<p>Found <b>3</b> records.</p>", plan(undated).get(0).detail());
        IssueOptions o = new IssueOptions(true, false, Risk.LOW, "https://scan.hirdman.pro");
        String url = "https://scan.hirdman.pro/?domain=example.com";
        assertEquals("<p>Found <b>3</b> records.</p><p>Latest scan of example.com and its subdomains: <a href=\"" + url + "\">" + url
                + "</a>. Its counts can differ from this issue.</p>", IssuePlanner.plan(undated, true, o, Set.of()).get(0).detail());
    }

    @Test
    void onlyAPlainServerAddressBecomesALink() {
        assertEquals(java.util.Optional.empty(), IssuePlanner.siteUrl("example.com", "javascript:alert(1)//"));
        assertEquals(java.util.Optional.empty(), IssuePlanner.siteUrl("example.com", "https://x\"><img src=x>"));
        assertEquals("http://127.0.0.1:8080/?domain=example.com", IssuePlanner.siteUrl("example.com", "http://127.0.0.1:8080").orElseThrow());
    }

    @Test
    void serverHtmlMayLinkToTheRadarServer() {
        IssueOptions o = new IssueOptions(true, false, Risk.LOW, "https://radar.example.com:8443");
        Finding linked = new Finding("stealer_logs", "high", "tentative", "A", "<a href=\"https://radar.example.com/x\">r</a>"
                + "<a href=\"https://evil.example/\">e</a>", "", "");
        HostResult r = new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 3, 2, 0, 0, List.of(linked), null);
        assertTrue(IssuePlanner.plan(r, true, o, Set.of()).get(0).detail().startsWith("<a href=\"https://radar.example.com/x\">r</a>"
                + "&lt;a href=&quot;https://evil.example/&quot;&gt;e&lt;/a&gt;"));
    }

    @Test
    void siteHostIsTheServerNameOrNull() {
        assertEquals("radar.example.com", IssuePlanner.siteHost("https://radar.example.com:8443"));
        assertEquals(null, IssuePlanner.siteHost("https://a]b"));
        assertEquals(null, IssuePlanner.siteHost("javascript:alert(1)//"));
        assertEquals(null, IssuePlanner.siteHost(null));
    }

    @Test
    void planDoesNotCopyTheReportedSet() {
        // The session's set grows with every issue; copying it per row made a scope-change pass take seconds.
        Set<String> noCopy = new java.util.AbstractSet<>() {
            @Override
            public boolean contains(Object o) {
                return false;
            }

            @Override
            public java.util.Iterator<String> iterator() {
                throw new AssertionError("copied");
            }

            @Override
            public int size() {
                throw new AssertionError("copied");
            }
        };
        assertEquals(1, IssuePlanner.plan(row(HostStatus.CHECKED, f(STEALER, "high")), true, DEFAULTS, noCopy).size());
    }

    @Test
    void notCheckedAndCleanGetNothing() {
        assertTrue(plan(row(HostStatus.NOT_CHECKED, f(STEALER, "high"))).isEmpty());
        assertTrue(plan(row(HostStatus.FOUND, f(STEALER, "high"))).isEmpty());
        assertTrue(plan(row(HostStatus.CLEAN)).isEmpty());
    }

    @Test
    void outOfScopeSkippedByDefault() {
        HostResult r = row(HostStatus.CHECKED, f(STEALER, "high"), f(WORK, "medium"));
        assertTrue(IssuePlanner.plan(r, false, DEFAULTS, Set.of()).isEmpty());
        assertEquals(2, IssuePlanner.plan(r, false, new IssueOptions(true, true, Risk.LOW, null), Set.of()).size());
    }

    @Test
    void lowestSeverityFilters() {
        HostResult r = row(HostStatus.CHECKED, f(STEALER, "high"), f(WORK, "medium"), f("Low one", "low"));
        List<IssueSpec> specs = IssuePlanner.plan(r, true, new IssueOptions(true, false, Risk.MEDIUM, null), Set.of());
        assertEquals(List.of(P + STEALER, P + WORK), specs.stream().map(IssueSpec::name).toList());
    }

    @Test
    void skipsAlreadyReported() {
        HostResult r = row(HostStatus.CHECKED, f(STEALER, "high"), f(WORK, "medium"));
        List<IssueSpec> specs = IssuePlanner.plan(r, true, DEFAULTS, Set.of(P + STEALER + "|https://vpn.example.com/"));
        assertEquals(List.of(P + WORK), specs.stream().map(IssueSpec::name).toList());
    }

    @Test
    void sameNameTwiceGivesOneIssue() {
        assertEquals(1, plan(row(HostStatus.CHECKED, f(STEALER, "high"), f(STEALER, "high"))).size());
    }

    @Test
    void severityAndConfidenceAreBurpValues() {
        Finding odd = new Finding("x", "HIGH", "Firm", "A", "", "", "");
        Finding unknown = new Finding("x", "high", "sure", "B", null, null, null);
        List<IssueSpec> specs = plan(row(HostStatus.CHECKED, odd, unknown));
        assertEquals("high", specs.get(0).severity());
        assertEquals("firm", specs.get(0).confidence());
        assertEquals("tentative", specs.get(1).confidence());
        assertEquals(CHECKED, specs.get(1).detail());
    }

    @Test
    void nameIsOneLine() {
        assertEquals(P + "Infostealer records", plan(row(HostStatus.CHECKED, f("Infostealer\n  records‮", "high"))).get(0).name());
        assertTrue(plan(row(HostStatus.CHECKED, f(" \n", "high"), f(null, "high"))).isEmpty());
    }

    @Test
    void nameHasNoAngleBrackets() {
        // Burp shows the name in its own panes, where html.disable cannot be set.
        assertEquals(P + "htmlimg src=x Work accounts",
                plan(row(HostStatus.CHECKED, f("<html><img src=x> Work accounts", "high"))).get(0).name());
        assertTrue(plan(row(HostStatus.CHECKED, f("<>", "high"))).isEmpty());
    }

    @Test
    void serverHtmlKeepsOnlyPlainTags() {
        assertEquals("<p>a <b>b</b><br><i>c</i></p><ul><li>d</li></ul><ol><li>e</li></ol>",
                IssueHtml.clean("<p>a <b>b</b><br><i>c</i></p><ul><li>d</li></ul><ol><li>e</li></ol>"));
        assertEquals("&lt;img src=&quot;http://evil.example/x&quot;&gt;", IssueHtml.clean("<img src=\"http://evil.example/x\">"));
        assertEquals("&lt;script&gt;alert(1)&lt;/script&gt;", IssueHtml.clean("<script>alert(1)</script>"));
        assertEquals("&lt;a href=&#39;https://evil.example&#39;&gt;l&lt;/a&gt;", IssueHtml.clean("<a href='https://evil.example'>l</a>"));
        assertEquals("&lt;p onclick=&quot;x&quot;&gt;p&lt;/p&gt;", IssueHtml.clean("<p onclick=\"x\">p</p>"));
        assertEquals("&lt;B&gt;caps&lt;/B&gt;", IssueHtml.clean("<B>caps</B>"));
    }

    @Test
    void httpsLinksFromTheServerStayAndOtherLinksAreText() {
        String ref = "<li><a href=\"https://attack.mitre.org/techniques/T1539/\">MITRE ATT&amp;CK T1539</a></li>";
        assertEquals(ref, IssueHtml.clean(ref));
        assertEquals("<a href=\"https://cwe.mitre.org/data/definitions/522.html\">CWE-522</a>",
                IssueHtml.clean("<a href=\"https://cwe.mitre.org/data/definitions/522.html\">CWE-522</a>"));
        assertEquals("&lt;a href=&quot;http://x.example/&quot;&gt;l&lt;/a&gt;", IssueHtml.clean("<a href=\"http://x.example/\">l</a>"));
        assertEquals("&lt;a href=&quot;javascript:alert(1)&quot;&gt;l&lt;/a&gt;", IssueHtml.clean("<a href=\"javascript:alert(1)\">l</a>"));
        assertEquals("&lt;a href=&quot;https://owasp.org/&quot; onclick=&quot;y&quot;&gt;l&lt;/a&gt;",
                IssueHtml.clean("<a href=\"https://owasp.org/\" onclick=\"y\">l</a>"));
        assertEquals("&lt;a href=&quot;https://owasp.org/a b&quot;&gt;l&lt;/a&gt;", IssueHtml.clean("<a href=\"https://owasp.org/a b\">l</a>"));
        assertEquals("&lt;a href=&quot;https://owasp.org/&amp;&quot;&gt;l&lt;/a&gt;", IssueHtml.clean("<a href=\"https://owasp.org/&\">l</a>"));
        assertEquals("&lt;A HREF=&quot;https://owasp.org/&quot;&gt;l&lt;/A&gt;", IssueHtml.clean("<A HREF=\"https://owasp.org/\">l</A>"));
        // A link never stays open and never nests.
        assertEquals("<a href=\"https://owasp.org/\">l</a>", IssueHtml.clean("<a href=\"https://owasp.org/\">l"));
        assertEquals("<a href=\"https://owasp.org/\">&lt;a href=&quot;https://cwe.mitre.org/&quot;&gt;l</a>&lt;/a&gt;",
                IssueHtml.clean("<a href=\"https://owasp.org/\"><a href=\"https://cwe.mitre.org/\">l</a></a>"));
        assertEquals("&lt;a href=&quot;https://" + "x".repeat(400) + "/&quot;&gt;",
                IssueHtml.clean("<a href=\"https://" + "x".repeat(400) + "/\">"));
    }

    @Test
    void entitiesStayAndBareAmpersandsAreEscaped() {
        assertEquals("1 &lt; 2 &amp;&amp; \u2022 &nbsp; a &amp; b &amp;bogus", IssueHtml.clean("1 &lt; 2 && &#8226; &nbsp; a & b &bogus"));
    }

    @Test
    void controlAndBidiCharsAreDroppedAndLengthCapped() {
        assertEquals("ab\ncd", IssueHtml.clean("a\u0000b\n‮cd\u0007"));
        assertEquals(IssueHtml.MAX_LENGTH, IssueHtml.clean("x".repeat(IssueHtml.MAX_LENGTH + 50)).length());
        assertEquals("", IssueHtml.clean(null));
    }

    @Test
    void baseUrlIsHttpsRoot() {
        assertEquals("https://vpn.example.com/", IssuePlanner.baseUrl("vpn.example.com"));
    }

    @Test
    void everyHtmlFieldIsCleaned() {
        Finding bad = new Finding("x", "high", "tentative", "A", "<script>d</script>", "<img src=x>", "<a href=y>r</a>");
        IssueSpec spec = plan(row(HostStatus.CHECKED, bad)).get(0);
        assertEquals("&lt;script&gt;d&lt;/script&gt;" + CHECKED, spec.detail());
        assertEquals("&lt;img src=x&gt;", spec.background());
        assertEquals("&lt;a href=y&gt;r&lt;/a&gt;", spec.remediation());
    }

    @Test
    void unknownSeverityIsInformationWhenEverythingIsReported() {
        HostResult r = row(HostStatus.CHECKED, f(STEALER, "info"));
        assertTrue(plan(r).isEmpty());
        assertEquals("information", IssuePlanner.plan(r, true, new IssueOptions(true, false, Risk.NONE, null), Set.of()).get(0).severity());
    }

    @Test
    void breachSourcesComeBeforeTheCheckedLine() {
        HostResult r = new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 3, 2, 0, 0, List.of(f(STEALER, "high")),
                CHECKED_AT, List.of(new pro.hirdman.radar.api.ServerEvent.BreachSource("Stealer Logs", "2024-03", 12),
                        new pro.hirdman.radar.api.ServerEvent.BreachSource("<b>AT&T</b>", null, 3)));
        assertEquals("<p>Found <b>3</b> records.</p><p>Breach sources for this host: Stealer Logs: 12 (2024-03); "
                + "&lt;b&gt;AT&amp;T&lt;/b&gt;: 3.</p>" + CHECKED, plan(r).get(0).detail());
    }

    @Test
    void serverHtmlComesOutBalanced() {
        // Burp puts issue fields next to its own markup in panels and reports; nothing may stay open or close Burp's tags.
        assertEquals("<ul><li><b>a</b></li></ul>", IssueHtml.clean("<ul><li><b>a"));
        assertEquals("<b><i>x</i></b>&lt;/i&gt;", IssueHtml.clean("<b><i>x</b></i>"));
        assertEquals("a&lt;/ul&gt;&lt;/p&gt;b", IssueHtml.clean("a</ul></p>b"));
        assertEquals("<a href=\"https://owasp.org/\">l <b>b</b></a>", IssueHtml.clean("<a href=\"https://owasp.org/\">l <b>b"));
        assertEquals("<b><a href=\"https://owasp.org/\">l</a></b>", IssueHtml.clean("<b><a href=\"https://owasp.org/\">l</b>"));
        assertEquals("<a href=\"https://owasp.org/\">&lt;a href=&quot;https://cwe.mitre.org/&quot;&gt;l</a>",
                IssueHtml.clean("<a href=\"https://owasp.org/\"><a href=\"https://cwe.mitre.org/\">l"));
        assertEquals("<ul><li>" + "x".repeat(IssueHtml.MAX_LENGTH - 8) + "</li></ul>",
                IssueHtml.clean("<ul><li>" + "x".repeat(IssueHtml.MAX_LENGTH) + "</li></ul>"));
    }
}
