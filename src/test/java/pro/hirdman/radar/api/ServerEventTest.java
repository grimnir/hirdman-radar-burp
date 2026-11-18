package pro.hirdman.radar.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonParser;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ServerEventTest {

    // The check event from the server's API reference, verbatim.
    static final String CHECK = """
            {
              "domain": "vpn.example.com",
              "hc_corp_found": 4,
              "hc_origin_found": 0,
              "db_email_count": 12,
              "db_url_count": 3,
              "source": "burp",
              "breach_sources": [{"name": "Stealer Logs", "count": 4}],
              "stealer_count": 4,
              "hc_checked": true,
              "findings": [
                {
                  "kind": "stealer_logs",
                  "severity": "high",
                  "confidence": "tentative",
                  "name": "Infostealer records linked to host",
                  "detail": "<p>…</p>",
                  "background": "<p>…</p>",
                  "remediation": "<p>…</p>"
                }
              ]
            }
            """;

    static JobEvent event(String name, String data) {
        return new JobEvent(1, name, JsonParser.parseString(data));
    }

    static ServerEvent parse(String name, String data) throws MalformedEventException {
        return ServerEvent.parse(event(name, data)).orElseThrow();
    }

    @Test
    void checkEventWithFindings() throws Exception {
        ServerEvent.Check c = (ServerEvent.Check) parse("subdomain_check", CHECK);
        assertEquals("vpn.example.com", c.domain());
        assertEquals(4, c.stealerCount());
        assertEquals(4, c.hcCorpFound());
        assertEquals(0, c.hcOriginFound());
        assertEquals(12, c.dbEmailCount());
        assertEquals(3, c.dbUrlCount());
        assertTrue(c.checked());
        assertFalse(c.root());
        assertEquals(1, c.findings().size());
        ServerEvent.Finding f = c.findings().get(0);
        assertEquals("stealer_logs", f.kind());
        assertEquals("high", f.severity());
        assertEquals("tentative", f.confidence());
        assertEquals("Infostealer records linked to host", f.name());
        assertEquals("<p>…</p>", f.remediation());
    }

    @Test
    void missingHcCheckedMeansNotChecked() throws Exception {
        ServerEvent.Check c = (ServerEvent.Check) parse("subdomain_check", "{\"domain\":\"a.example.com\"}");
        assertFalse(c.checked());
        assertTrue(c.findings().isEmpty());
    }

    @Test
    void hcCheckedFalseIsNotChecked() throws Exception {
        ServerEvent.Check c = (ServerEvent.Check) parse("subdomain_check", "{\"domain\":\"a.example.com\",\"hc_checked\":false}");
        assertFalse(c.checked());
    }

    @Test
    void domainCheckIsRoot() throws Exception {
        ServerEvent.Check c = (ServerEvent.Check) parse("domain_check", CHECK);
        assertTrue(c.root());
        assertEquals("vpn.example.com", c.domain());
        assertEquals(1, c.findings().size());
    }

    @Test
    void cachedScanStarted() throws Exception {
        ServerEvent.ScanStarted cached = (ServerEvent.ScanStarted) parse("scan_started",
                "{\"cached\":\"true\",\"domain\":\"example.com\",\"mode\":\"basic\",\"scan_id\":\"x\"}");
        assertTrue(cached.cached());

        ServerEvent.ScanStarted fresh = (ServerEvent.ScanStarted) parse("scan_started", "{\"scan_id\":\"x\",\"hosts\":2}");
        assertFalse(fresh.cached());
        assertEquals(2, fresh.hosts());
    }

    @Test
    void queuedProgressDone() throws Exception {
        assertEquals(new ServerEvent.Queued(2, 40), parse("queued", "{\"position\":2,\"eta_sec\":40}"));
        assertEquals(new ServerEvent.Progress(37, 120), parse("progress", "{\"checked\":37,\"total\":120}"));
        assertEquals(new ServerEvent.Done(120, 3),
                parse("done", "{\"total_subdomains\":120,\"unchecked_hosts\":3,\"duration_sec\":81.5}"));
    }

    @Test
    void unknownEventIgnored() throws Exception {
        assertEquals(Optional.empty(), ServerEvent.parse(event("db_stats", "{\"total\":5}")));
    }

    @Test
    void brokenDataThrows() {
        assertThrows(MalformedEventException.class, () -> ServerEvent.parse(event("progress", "\"x\"")));
        assertThrows(MalformedEventException.class, () -> ServerEvent.parse(event("progress", "{\"checked\":\"many\"}")));
        assertThrows(MalformedEventException.class, () -> ServerEvent.parse(new JobEvent(1, "done", null)));
    }

    @Test
    void errorMessageIsOneLine() throws Exception {
        String data = "{\"message\":\"a\\r\\nb\\t" + "x".repeat(400) + "\"}";
        ServerEvent.ErrorEvent e = (ServerEvent.ErrorEvent) parse("error", data);
        assertTrue(e.message().startsWith("a b"), e.message());
        assertFalse(e.message().contains("\r") || e.message().contains("\n") || e.message().contains("\t"));
        assertEquals(300, e.message().length());
    }

    @Test
    void findingsOfOneKindShareTheirTexts() {
        // Read twice from JSON, as rows of a big project are: the long texts must not be held once per row.
        String json = "{\"kind\":\"stealer_logs\",\"severity\":\"high\",\"confidence\":\"tentative\",\"name\":\"N\","
                + "\"detail\":\"<p>d</p>\",\"background\":\"<p>long background</p>\",\"remediation\":\"<p>long remediation</p>\"}";
        ServerEvent.Finding a = Json.GSON.fromJson(json, ServerEvent.Finding.class);
        ServerEvent.Finding b = Json.GSON.fromJson(json, ServerEvent.Finding.class);
        assertSame(a.background(), b.background());
        assertSame(a.remediation(), b.remediation());
        assertSame(a.name(), b.name());
        assertSame(a.kind(), b.kind());
        assertSame(a.severity(), b.severity());
        assertSame(a.confidence(), b.confidence());
    }

    @Test
    void checkCarriesBreachSourcesWithPlainDates() throws Exception {
        ServerEvent.Check c = (ServerEvent.Check) parse("subdomain_check", """
                {"domain":"a.example.com","hc_checked":true,"breach_sources":[
                  {"name":"Stealer Logs","date":"2024-03-15T00:00:00Z","count":4},
                  {"name":"Old\\nList","date":"soon","count":-2},
                  {"name":"Y","date":"2012"},
                  null]}
                """);
        assertEquals(List.of(new ServerEvent.BreachSource("Stealer Logs", "2024-03-15", 4),
                new ServerEvent.BreachSource("Old List", null, 0), new ServerEvent.BreachSource("Y", "2012", 0)), c.breachSources());
        assertTrue(((ServerEvent.Check) parse("subdomain_check", "{\"domain\":\"a.example.com\"}")).breachSources().isEmpty());
    }

    @Test
    void findingTextsAreCutBeforeTheyAreKept() {
        String big = "x".repeat(20_000);
        ServerEvent.Finding f = new ServerEvent.Finding("stealer", "high", "firm", "n".repeat(1000), big, big, big);
        assertEquals(300, f.name().length());
        assertEquals(10_000, f.detail().length());
        assertEquals(10_000, f.background().length());
        assertEquals(10_000, f.remediation().length());
        ServerEvent.Finding empty = new ServerEvent.Finding(null, null, null, null, null, null, null);
        assertEquals(null, empty.name());
        assertEquals(null, empty.detail());
        assertEquals("short", new ServerEvent.Finding("k", "s", "c", "short", "d", "b", "r").name());
        assertEquals("n".repeat(299), new ServerEvent.Finding("k", "s", "c", "n".repeat(299), "d", "b", "r").name());
        assertEquals("n".repeat(300), new ServerEvent.Finding("k", "s", "c", "n".repeat(300), "d", "b", "r").name());
    }
}
