package pro.hirdman.radar.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class ResponsesTest {

    // Fixtures copied verbatim from the server's API reference.
    static final String META = """
            {
              "api_version": 1,
              "min_plugin_version": "0.1.0",
              "key_name": "anonymous",
              "limits": {"max_hosts": 50, "hosts_per_sec": 1.5, "hosts_per_hour": 300},
              "notes": {
                "database": "Partial check against about a third of the HIRDMAN leak archive.",
                "coverage": "The automated check covers about a third of a full HIRDMAN review.",
                "counts_only": "Counts only: no accounts, passwords, raw records or dumps."
              }
            }
            """;

    static final String PAGE = """
            {
              "events": [
                {"seq": 1, "event": "queued", "data": {"position": 1, "eta_sec": 40}},
                {"seq": 2, "event": "scan_started", "data": {"scan_id": "…", "domain": "example.com", "mode": "basic"}}
              ],
              "next": 2,
              "done": false
            }
            """;

    static final String SUBDOMAINS = """
            {
              "domain": "example.com",
              "subdomains": [{"host": "vpn.example.com", "priority": 3}, {"host": "blog.example.com", "priority": 0}],
              "failed_sources": ["crtsh"],
              "duration_sec": 4.2
            }
            """;

    @Test
    void metaParses() {
        Meta m = Json.GSON.fromJson(META, Meta.class);
        assertEquals(1, m.apiVersion());
        assertEquals("0.1.0", m.minPluginVersion());
        assertEquals("anonymous", m.keyName());
        assertEquals(new Meta.Limits(50, 1.5, 300), m.limits());
        assertTrue(m.notes().countsOnly().startsWith("Counts only"));
        assertTrue(m.notes().coverage().startsWith("The automated check"));
    }

    @Test
    void metaHostsLeftIsReadWhenSent() {
        Meta m = Json.GSON.fromJson(META.replace("\"hosts_per_hour\": 300", "\"hosts_per_hour\": 300, \"hosts_left\": 120"),
                Meta.class);
        assertEquals(new Meta.Limits(50, 1.5, 300, 120), m.limits());
        assertNull(Json.GSON.fromJson(META, Meta.class).limits().hostsLeft());
    }

    @Test
    void jobPageParses() {
        JobPage p = Json.GSON.fromJson(PAGE, JobPage.class);
        assertEquals(2, p.events().size());
        assertEquals(2, p.next());
        assertFalse(p.done());
        assertEquals("queued", p.events().get(0).event());
        assertEquals(1, p.events().get(0).seq());
        assertEquals(40, p.events().get(0).data().getAsJsonObject().get("eta_sec").getAsInt());
    }

    @Test
    void emptyJobPageHasNoEvents() {
        JobPage p = Json.GSON.fromJson("{\"next\":7,\"done\":true}", JobPage.class);
        assertTrue(p.events().isEmpty());
        assertTrue(p.done());
    }

    @Test
    void subdomainsParse() {
        SubdomainList s = Json.GSON.fromJson(SUBDOMAINS, SubdomainList.class);
        assertEquals("example.com", s.domain());
        assertEquals(List.of(new SubdomainList.Subdomain("vpn.example.com", 3), new SubdomainList.Subdomain("blog.example.com", 0)),
                s.subdomains());
        assertEquals(List.of("crtsh"), s.failedSources());
    }

    @Test
    void jobRequestJson() {
        assertEquals("{\"domain\":\"example.com\",\"rescan\":true}", JobRequest.ofDomain("example.com", true).toJson());
        assertEquals("{\"domain\":\"example.com\",\"rescan\":false}", JobRequest.ofDomain("example.com", false).toJson());
        assertEquals("{\"hosts\":[\"a\",\"b\"]}", JobRequest.ofHosts(List.of("a", "b")).toJson());
    }

    @Test
    void oneLineHandlesNullAndShortText() {
        assertNull(Json.oneLine(null));
        assertEquals("plain", Json.oneLine("  plain "));
        assertEquals("a b", Json.oneLine("a\u0000\u001b\u0085b"));
        // Bidi overrides could make a server string read differently in Burp.
        assertEquals("evil txt.exe", Json.oneLine("evil‮txt.exe"));
    }
}
