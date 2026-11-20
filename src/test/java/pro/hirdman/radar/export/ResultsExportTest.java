package pro.hirdman.radar.export;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.LoginPage;

class ResultsExportTest {

    static final Instant AT = Instant.parse("2026-11-17T20:00:00Z");

    static Finding f(String name, String severity) {
        return new Finding("stealer", severity, "firm", name, "<p>Found <b>3</b> records.</p>", "<p>Why.</p>", "<p>Fix.</p>");
    }

    final HostResult leaky = new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 12, 3, 1, 40,
            List.of(f("Infostealer records linked to host", "high"), f("Work accounts found in breaches", "high")), AT,
            List.of(new BreachSource("Stealer Logs", "2024-03", 12), new BreachSource("Collection #1", null, 3)));
    final HostResult unknown = new HostResult("old.example.com", "example.com", HostStatus.NOT_CHECKED, 0, 0, 0, 0, List.of(), AT);
    final HostResult found = new HostResult("new.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null);
    final List<HostResult> rows = List.of(leaky, unknown, found);

    @Test
    void jsonHasCountsAndFindingNamesOnly() {
        String json = ResultsExport.json("example.com", rows, h -> h.startsWith("vpn."), "https://scan.hirdman.pro", "0.1.0",
                Instant.parse("2026-11-17T21:00:00Z"));
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        assertEquals("Hirdman Radar", root.get("tool").getAsString());
        assertEquals("0.1.0", root.get("version").getAsString());
        assertEquals("2026-11-17T21:00:00Z", root.get("exported_at").getAsString());
        assertEquals("example.com", root.get("domain").getAsString());
        assertEquals("https://scan.hirdman.pro/?domain=example.com", root.get("report_url").getAsString());
        assertEquals("Counts only: no accounts, passwords, raw records or dumps.", root.get("note").getAsString());
        assertEquals(3, root.getAsJsonArray("hosts").size());

        JsonObject h = root.getAsJsonArray("hosts").get(0).getAsJsonObject();
        assertEquals("vpn.example.com", h.get("host").getAsString());
        assertEquals("Checked (leaks found)", h.get("status").getAsString());
        assertEquals("High", h.get("risk").getAsString());
        assertTrue(h.get("in_scope").getAsBoolean());
        assertEquals(12, h.get("stealer").getAsInt());
        assertEquals(3, h.get("work_accounts").getAsInt());
        assertEquals(1, h.get("personal_accounts").getAsInt());
        assertEquals(40, h.get("db_records").getAsLong());
        assertEquals("2026-11-17T20:00:00Z", h.get("checked_at").getAsString());
        JsonObject finding = h.getAsJsonArray("findings").get(0).getAsJsonObject();
        assertEquals("Infostealer records linked to host", finding.get("name").getAsString());
        assertEquals("high", finding.get("severity").getAsString());
        assertEquals("firm", finding.get("confidence").getAsString());
        assertEquals("stealer", finding.get("kind").getAsString());
        assertEquals(4, finding.size(), "server texts stay out: " + finding);
        assertEquals("2024-03", h.get("latest_breach").getAsString());
        JsonObject source = h.getAsJsonArray("breach_sources").get(1).getAsJsonObject();
        assertEquals("Collection #1", source.get("name").getAsString());
        assertTrue(source.get("date").isJsonNull());
        assertEquals(3, source.get("count").getAsInt());

        JsonObject n = root.getAsJsonArray("hosts").get(1).getAsJsonObject();
        assertEquals("Check failed", n.get("status").getAsString());
        assertFalse(n.get("in_scope").getAsBoolean());
        assertTrue(n.get("stealer").isJsonNull(), "unknown counts are null, never 0");
        assertTrue(n.get("latest_breach").isJsonNull());
        assertTrue(n.get("breach_sources").isJsonNull());
        assertTrue(root.getAsJsonArray("hosts").get(2).getAsJsonObject().get("checked_at").isJsonNull());
    }

    @Test
    void theLoginPageSeenInTrafficIsExported() {
        HostResult r = rows.get(0).withLogin(new LoginPage(LoginPage.Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login"));
        JsonArray hosts = JsonParser.parseString(ResultsExport.json("example.com", List.of(r, rows.get(1)), h -> true, null, "0.1.0",
                AT)).getAsJsonObject().getAsJsonArray("hosts");
        JsonObject login = hosts.get(0).getAsJsonObject().getAsJsonObject("login_page");
        assertEquals("FortiGate SSL VPN", login.get("type").getAsString());
        assertEquals("/remote/login", login.get("path").getAsString());
        assertTrue(hosts.get(1).getAsJsonObject().get("login_page").isJsonNull());
        assertTrue(ResultsExport.csv(List.of(r), h -> true).strip().endsWith(",FortiGate SSL VPN at /remote/login,"),
                ResultsExport.csv(List.of(r), h -> true));
    }

    @Test
    void jsonWithoutASiteHasNoReportUrl() {
        JsonObject root = JsonParser.parseString(ResultsExport.json("example.com", List.of(), h -> false, null, "0.1.0", AT))
                .getAsJsonObject();
        assertTrue(root.get("report_url").isJsonNull());
    }

    @Test
    void csvHasOneLinePerHost() {
        assertEquals("""
                host,domain,status,risk,scope,stealer,work_accounts,personal_accounts,db_records,latest_breach,checked_at,breach_sources,\
                findings,login_page,change
                vpn.example.com,example.com,Checked (leaks found),High,in,12,3,1,40,2024-03,2026-11-17T20:00:00Z,Stealer Logs: 12 (2024-03); \
                Collection #1: 3,Infostealer records linked to host (high); Work accounts found in breaches (high),,
                old.example.com,example.com,Check failed,,out,,,,,,2026-11-17T20:00:00Z,,,,
                new.example.com,example.com,Not checked yet,,out,,,,,,,,,,
                """, ResultsExport.csv(rows, h -> h.startsWith("vpn.")));
    }

    @Test
    void csvQuotesCellsAndDefusesFormulas() {
        HostResult odd = new HostResult("a.example.com", "example.com", HostStatus.CHECKED, 1, 0, 0, 0,
                List.of(f("=HYPERLINK(\"http://x\",\"y\")", "low")), AT);
        String line = ResultsExport.csv(List.of(odd), h -> false).split("\n")[1];
        assertTrue(line.endsWith(",\"'=HYPERLINK(\"\"http://x\"\",\"\"y\"\") (low)\",,"), line);
        assertEquals("", ResultsExport.cell(""));
        assertEquals("'+1", ResultsExport.cell("+1"));
        assertEquals("'-1", ResultsExport.cell("-1"));
        assertEquals("'@a", ResultsExport.cell("@a"));
        assertEquals("\"a,b\"", ResultsExport.cell("a,b"));
        assertEquals("\"a\nb\"", ResultsExport.cell("a\nb"));
        assertEquals("\"a\rb\"", ResultsExport.cell("a\rb"));
        assertEquals("\"say \"\"hi\"\"\"", ResultsExport.cell("say \"hi\""));
    }

    @Test
    void fileNameNamesTheDomain() {
        assertEquals("hirdman-radar-example.com.json", ResultsExport.fileName("example.com", "json"));
        assertEquals("hirdman-radar-results.csv", ResultsExport.fileName(null, "csv"));
    }

    @Test
    void theChangeSinceThePreviousCheckIsExported() {
        HostResult again = leaky.withPrevious(new HostResult.Previous(2, 3, 1, 41, AT.minusSeconds(3600)));
        HostResult first = leaky.withPrevious(HostResult.Previous.FIRST);
        String csv = ResultsExport.csv(List.of(again, first, unknown), h -> true);
        String[] lines = csv.split("\n");
        assertTrue(lines[1].endsWith(",\"Infostealer +10, DB records -1\""), lines[1]);
        assertTrue(lines[2].endsWith(",new"), lines[2]);
        assertTrue(lines[3].endsWith(","), lines[3]);

        JsonArray hosts = JsonParser.parseString(ResultsExport.json("example.com", List.of(again, first, unknown), h -> true, null,
                "0.1.0", AT)).getAsJsonObject().getAsJsonArray("hosts");
        JsonObject p = hosts.get(0).getAsJsonObject().getAsJsonObject("previous");
        assertEquals(2, p.get("stealer").getAsInt());
        assertEquals(3, p.get("work_accounts").getAsInt());
        assertEquals(1, p.get("personal_accounts").getAsInt());
        assertEquals(41, p.get("db_records").getAsLong());
        assertEquals("2026-11-17T19:00:00Z", p.get("checked_at").getAsString());
        assertTrue(hosts.get(1).getAsJsonObject().getAsJsonObject("previous").get("checked_at").isJsonNull());
        assertTrue(hosts.get(2).getAsJsonObject().get("previous").isJsonNull());
    }
}
