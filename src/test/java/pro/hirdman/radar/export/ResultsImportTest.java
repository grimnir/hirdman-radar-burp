package pro.hirdman.radar.export;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.issues.IssueOptions;
import pro.hirdman.radar.issues.IssuePlanner;
import pro.hirdman.radar.issues.IssueSpec;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostResult.Previous;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.LoginPage;
import pro.hirdman.radar.model.Risk;

class ResultsImportTest {

    static final Instant AT = Instant.parse("2026-11-17T20:00:00Z");
    static final Instant NOW = Instant.parse("2026-11-18T09:00:00Z");

    static Finding f(String kind, String name, String severity) {
        return new Finding(kind, severity, "tentative", name, "<p>server detail</p>", "<p>Why.</p>", "<p>Fix.</p>");
    }

    final HostResult leaky = new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 12, 3, 1, 40,
            List.of(f("stealer_logs", "Infostealer records linked to host", "high"),
                    f("work_accounts", "Work accounts found in breaches", "high")), AT,
            List.of(new BreachSource("Stealer Logs", "2024-03", 12), new BreachSource("Collection #1", null, 3)))
            .withLogin(new LoginPage(LoginPage.Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login"))
            .withPrevious(new Previous(2, 3, 1, 41, AT.minusSeconds(3600)));
    final HostResult clean = new HostResult("dev.example.com", "example.com", HostStatus.CLEAN, 0, 0, 0, 0, List.of(), AT)
            .withLogin(new LoginPage(LoginPage.Kind.PASSWORD_FORM, "Password form", "/login"))
            .withPrevious(Previous.FIRST);
    final HostResult failed = new HostResult("old.example.com", "example.com", HostStatus.NOT_CHECKED, 0, 0, 0, 0, List.of(), AT)
            .withLogin(new LoginPage(LoginPage.Kind.HTTP_AUTH, "NTLM sign-in", "/"))
            .withPrevious(new Previous(5, 0, 0, 0, AT.minusSeconds(60)));
    final HostResult found = new HostResult("new.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null);

    String export(List<HostResult> rows) {
        return ResultsExport.json("example.com", rows, h -> true, "https://scan.hirdman.pro", "0.2.0", NOW);
    }

    /** The export with {@code change} applied to its JSON tree. */
    String edited(Consumer<JsonObject> change) {
        JsonObject root = JsonParser.parseString(export(List.of(leaky, clean, failed, found))).getAsJsonObject();
        change.accept(root);
        return root.toString();
    }

    static JsonObject host(JsonObject root, int i) {
        return root.getAsJsonArray("hosts").get(i).getAsJsonObject();
    }

    String refusal(String json) {
        return assertThrows(ResultsImport.Refused.class, () -> ResultsImport.parse(json, NOW)).getMessage();
    }

    @Test
    void anExportComesBackAsTheSameRowsWithoutServerTexts() throws Exception {
        List<HostResult> back = ResultsImport.parse(export(List.of(leaky, clean, failed, found)), NOW);
        assertEquals(4, back.size());
        HostResult v = back.get(0);
        assertEquals(List.of("vpn.example.com", "example.com", HostStatus.CHECKED), List.of(v.host(), v.domain(), v.status()));
        assertEquals(List.of(12, 3, 1), List.of(v.stealer(), v.work(), v.personal()));
        assertEquals(40, v.dbRecords());
        assertEquals(AT, v.checkedAt());
        assertEquals(leaky.sources(), v.sources());
        assertEquals(leaky.login(), v.login());
        assertEquals(leaky.previous(), v.previous());
        assertEquals(Risk.HIGH, v.risk());
        assertFalse(v.replayed());
        assertEquals(List.of(new Finding("stealer_logs", "high", "tentative", "Infostealer records linked to host", null, null, null),
                new Finding("work_accounts", "high", "tentative", "Work accounts found in breaches", null, null, null)), v.findings());
        assertEquals(clean, back.get(1));
        assertEquals(failed, back.get(2));
        assertEquals(found, back.get(3));
    }

    @Test
    void anOlderExportWithoutKindsOrPreviousCountsIsRead() throws Exception {
        String old = edited(root -> {
            for (JsonElement h : root.getAsJsonArray("hosts")) {
                h.getAsJsonObject().remove("previous");
                for (JsonElement f : h.getAsJsonObject().getAsJsonArray("findings")) {
                    f.getAsJsonObject().remove("kind");
                }
            }
        });
        HostResult v = ResultsImport.parse(old, NOW).get(0);
        assertNull(v.previous());
        assertNull(v.findings().get(0).kind());
        assertEquals("Infostealer records linked to host", v.findings().get(0).name());
    }

    @Test
    void namesAreNormalizedAsEverywhereElse() throws Exception {
        String json = edited(root -> {
            host(root, 0).addProperty("host", "VPN.Example.com.");
            host(root, 0).addProperty("domain", "EXAMPLE.com");
        });
        HostResult v = ResultsImport.parse(json, NOW).get(0);
        assertEquals("vpn.example.com", v.host());
        assertEquals("example.com", v.domain());
    }

    @Test
    void anythingButAnExportIsRefused() {
        assertEquals("the file is not JSON", refusal("{not json"));
        assertEquals("the file is not a Hirdman Radar JSON export", refusal("[1, 2]"));
        assertEquals("the file is not a Hirdman Radar JSON export", refusal("{\"tool\": \"Other\", \"hosts\": []}"));
        assertEquals("the file is not a Hirdman Radar JSON export", refusal("{\"hosts\": []}"));
        assertEquals("the file has no host list", refusal("{\"tool\": \"Hirdman Radar\"}"));
        assertEquals("the file is empty", refusal("  "));
    }

    @Test
    void unknownFieldsAreRefusedWithTheirPlace() {
        assertEquals("unknown field \"extra\"", refusal(edited(root -> root.addProperty("extra", 1))));
        assertEquals("host 2 (dev.example.com): unknown field \"script\"",
                refusal(edited(root -> host(root, 1).addProperty("script", "x"))));
        assertEquals("host 1 (vpn.example.com): finding 1: unknown field \"detail\"",
                refusal(edited(root -> host(root, 0).getAsJsonArray("findings").get(0).getAsJsonObject().addProperty("detail", "<b>"))));
        assertEquals("host 1 (vpn.example.com): breach_sources: unknown field \"url\"",
                refusal(edited(root -> host(root, 0).getAsJsonArray("breach_sources").get(0).getAsJsonObject().addProperty("url", "x"))));
        assertEquals("host 1 (vpn.example.com): login_page: unknown field \"html\"",
                refusal(edited(root -> host(root, 0).getAsJsonObject("login_page").addProperty("html", "x"))));
        assertEquals("host 1 (vpn.example.com): previous: unknown field \"risk\"",
                refusal(edited(root -> host(root, 0).getAsJsonObject("previous").addProperty("risk", "x"))));
        String longName = "x".repeat(500);
        assertEquals("unknown field \"" + "x".repeat(40) + "...\"", refusal(edited(root -> root.addProperty(longName, 1))));
    }

    @Test
    void countsMustBeWholeAndNotNegative() {
        assertEquals("host 1 (vpn.example.com): stealer is not a whole number of 0 or more",
                refusal(edited(root -> host(root, 0).addProperty("stealer", -1))));
        assertEquals("host 1 (vpn.example.com): work_accounts is not a whole number of 0 or more",
                refusal(edited(root -> host(root, 0).addProperty("work_accounts", 1.5))));
        assertEquals("host 1 (vpn.example.com): personal_accounts is not a whole number of 0 or more",
                refusal(edited(root -> host(root, 0).addProperty("personal_accounts", "3"))));
        assertEquals("host 1 (vpn.example.com): stealer is not a whole number of 0 or more",
                refusal(edited(root -> host(root, 0).addProperty("stealer", 3_000_000_000L))));
        assertEquals("host 1 (vpn.example.com): db_records is missing",
                refusal(edited(root -> host(root, 0).remove("db_records"))));
        assertEquals("host 1 (vpn.example.com): breach_sources: count is not a whole number of 0 or more",
                refusal(edited(root -> host(root, 0).getAsJsonArray("breach_sources").get(0).getAsJsonObject().addProperty("count", -2))));
        assertEquals("host 1 (vpn.example.com): previous: db_records is not a whole number of 0 or more",
                refusal(edited(root -> host(root, 0).getAsJsonObject("previous").addProperty("db_records", -2))));
        assertEquals("host 3 (old.example.com): a failed check has no counts",
                refusal(edited(root -> host(root, 2).addProperty("stealer", 4))));
        assertEquals("host 4 (new.example.com): a host not checked yet has no findings",
                refusal(edited(root -> host(root, 3).getAsJsonArray("findings").add(new JsonObject()))));
    }

    @Test
    void namesStatusesAndTimesMustBeValid() {
        assertEquals("host 1: host \"10.0.0.1\" is not a host name", refusal(edited(root -> host(root, 0).addProperty("host", "10.0.0.1"))));
        assertEquals("host 1 (vpn.example.com): host is not under its domain other.org",
                refusal(edited(root -> host(root, 0).addProperty("domain", "other.org"))));
        assertEquals("host 1 (vpn.example.com): unknown status \"Hacked\"",
                refusal(edited(root -> host(root, 0).addProperty("status", "Hacked"))));
        assertEquals("host 1 (vpn.example.com): status says nothing found but the host has findings",
                refusal(edited(root -> host(root, 0).addProperty("status", "Checked (nothing found)"))));
        assertEquals("host 2 (dev.example.com): status says leaks found but the host has no findings",
                refusal(edited(root -> host(root, 1).addProperty("status", "Checked (leaks found)"))));
        assertEquals("host 1 (vpn.example.com): checked_at is not a time",
                refusal(edited(root -> host(root, 0).addProperty("checked_at", "yesterday"))));
        assertEquals("host 1 (vpn.example.com): checked_at is in the future",
                refusal(edited(root -> host(root, 0).addProperty("checked_at", "2027-01-01T00:00:00Z"))));
        assertEquals("host 1 (vpn.example.com): login_page is not one the plugin writes",
                refusal(edited(root -> host(root, 0).getAsJsonObject("login_page").addProperty("type", "<img src=x>"))));
        assertEquals("host 1 (vpn.example.com): login_page is not one the plugin writes",
                refusal(edited(root -> host(root, 0).getAsJsonObject("login_page").addProperty("type", "Outlook on the web"))));
        assertEquals("host 1 (vpn.example.com): risk is not a risk", refusal(edited(root -> host(root, 0).addProperty("risk", "Total"))));
        assertEquals("host 1 (vpn.example.com): in_scope is not true or false",
                refusal(edited(root -> host(root, 0).addProperty("in_scope", "yes"))));
        assertEquals("host 1 (vpn.example.com): findings is not a list", refusal(edited(root -> host(root, 0).addProperty("findings", "x"))));
        assertEquals("host 1 (vpn.example.com): finding 1: name is not text",
                refusal(edited(root -> host(root, 0).getAsJsonArray("findings").get(0).getAsJsonObject().add("name", new JsonArray()))));
        assertEquals("host 1 (vpn.example.com): finding 1: name is too long",
                refusal(edited(root -> host(root, 0).getAsJsonArray("findings").get(0).getAsJsonObject().addProperty("name", "n".repeat(2000)))));
        assertEquals("host 2 is not an object", refusal(edited(root -> root.getAsJsonArray("hosts").set(1, new JsonArray()))));
        assertEquals("note is not text", refusal(edited(root -> root.add("note", new JsonObject()))));
    }

    @Test
    void sizeAndHostCountAreCapped() {
        assertEquals("the file has more than 2 hosts", assertThrows(ResultsImport.Refused.class,
                () -> ResultsImport.parse(export(List.of(leaky, clean, failed)), NOW, 2)).getMessage());
        String big = " ".repeat(ResultsImport.MAX_CHARS + 1);
        assertEquals("the file is too large", refusal(big));
    }

    @Test
    void textFromTheFileIsTextInIssues() throws Exception {
        String json = edited(root -> {
            JsonObject f = host(root, 0).getAsJsonArray("findings").get(0).getAsJsonObject();
            f.addProperty("name", "<script>alert(1)</script>");
            host(root, 0).getAsJsonArray("breach_sources").get(0).getAsJsonObject().addProperty("name", "<img src=x onerror=alert(1)>");
        });
        HostResult v = ResultsImport.parse(json, NOW).get(0);
        List<IssueSpec> issues = IssuePlanner.plan(v, true, new IssueOptions(true, false, Risk.LOW, "https://scan.hirdman.pro"), Set.of());
        assertFalse(issues.isEmpty());
        for (IssueSpec i : issues) {
            assertFalse(i.detail().contains("<img") || i.detail().contains("<script"), i.detail());
            assertTrue(i.detail().contains("&lt;img src=x onerror=alert(1)&gt;"), i.detail());
        }
    }
}
