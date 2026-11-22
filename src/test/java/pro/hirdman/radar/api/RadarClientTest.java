package pro.hirdman.radar.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.Version;

class RadarClientTest {

    @Test
    void clientForTheServerUrlOrNone() {
        Transport t = (m, u, h, b, timeout) -> new Reply(200, Map.of(), "{}");
        assertNotNull(RadarClient.of("https://scan.hirdman.pro/", t));
        assertEquals(null, RadarClient.of("http://scan.hirdman.pro", t));
        assertEquals(null, RadarClient.of(null, t));
    }

    FakeServer server;
    RadarClient client;

    @BeforeEach
    void setUp() throws Exception {
        server = FakeServer.start();
        client = new RadarClient(ConnectionSettings.of(server.uri().toString()), new JdkTransport());
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    ApiException fails(ThrowingCall call) {
        return assertThrows(ApiException.class, call::run);
    }

    interface ThrowingCall {
        void run() throws Exception;
    }

    @Test
    void sendsUserAgentAndNoKey() throws Exception {
        server.reply(200, ResponsesTest.META);
        Meta m = client.meta();
        assertEquals(50, m.limits().maxHosts());
        FakeServer.Recorded r = server.requests().get(0);
        assertEquals("GET", r.method());
        assertEquals("/api/v1/meta", r.path());
        assertEquals("HirdmanRadar/" + Version.current(), r.headers().get("user-agent"));
        assertEquals("application/json", r.headers().get("accept"));
        assertFalse(r.headers().containsKey("x-api-key"));
    }

    @Test
    void metaReadsTheOptionalReleaseFields() throws Exception {
        server.reply(200, "{\"api_version\":1,\"limits\":{\"max_hosts\":50,\"hosts_per_sec\":1.5,\"hosts_per_hour\":300},"
                + "\"latest_plugin_version\":\"0.2.0\",\"release_url\":\"https://example.org/r\","
                + "\"notes\":{\"counts_only\":\"c\",\"announcement\":\"Maintenance at 10:00 UTC\"}}");
        Meta m = client.meta();
        assertEquals("0.2.0", m.latestPluginVersion());
        assertEquals("https://example.org/r", m.releaseUrl());
        assertEquals("Maintenance at 10:00 UTC", m.notes().announcement());
        server.reply(200, ResponsesTest.META);
        Meta old = client.meta();
        assertEquals(null, old.latestPluginVersion());
        assertEquals(null, old.releaseUrl());
        assertEquals(null, old.notes().announcement());
    }

    @Test
    void metaWithoutLimitsIsMalformed() {
        server.reply(200, "{\"api_version\":1}");
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.meta()).kind());
        server.reply(200, "{\"api_version\":1,\"limits\":{\"max_hosts\":0}}");
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.meta()).kind());
    }

    @Test
    void subdomainsEncodesDomainAndRescan() throws Exception {
        server.reply(200, ResponsesTest.SUBDOMAINS).reply(200, ResponsesTest.SUBDOMAINS);
        assertEquals(2, client.subdomains("example.com", false).subdomains().size());
        client.subdomains("a&b=c.com", true);
        assertEquals("/api/v1/subdomains", server.requests().get(0).path());
        assertEquals("domain=example.com", server.requests().get(0).query());
        assertEquals("domain=a%26b%3Dc.com&rescan=true", server.requests().get(1).query());
    }

    @Test
    void startJobPostsDomain() throws Exception {
        server.reply(202, "{\"job_id\":\"j1\"}");
        assertEquals("j1", client.startJob(JobRequest.ofDomain("example.com", false)));
        FakeServer.Recorded r = server.requests().get(0);
        assertEquals("POST", r.method());
        assertEquals("/api/v1/jobs", r.path());
        assertEquals("{\"domain\":\"example.com\",\"rescan\":false}", r.body());
        assertEquals("application/json", r.headers().get("content-type"));
    }

    @Test
    void startJobPostsHosts() throws Exception {
        server.reply(202, "{\"job_id\":\"j2\"}");
        assertEquals("j2", client.startJob(JobRequest.ofHosts(List.of("a.example.com", "b.example.com"))));
        assertEquals("{\"hosts\":[\"a.example.com\",\"b.example.com\"]}", server.requests().get(0).body());
    }

    @Test
    void startJobRejectsOddJobId() {
        server.reply(202, "{\"job_id\":\"../admin\"}").reply(202, "{}");
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.startJob(JobRequest.ofDomain("a.com", false))).kind());
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.startJob(JobRequest.ofDomain("a.com", false))).kind());
    }

    @Test
    void pollSendsAfterAndParsesPage() throws Exception {
        server.reply(200, ResponsesTest.PAGE);
        JobPage p = client.poll("j1", 5);
        assertEquals("/api/v1/jobs/j1", server.requests().get(0).path());
        assertEquals("after=5", server.requests().get(0).query());
        assertEquals(2, p.events().size());
        assertEquals(2, p.next());
        assertFalse(p.done());
    }

    @Test
    void status401IsHttp401() {
        server.reply(401, "{\"error\":\"unauthorized\"}");
        ApiException e = fails(() -> client.meta());
        assertEquals(ApiException.Kind.HTTP, e.kind());
        assertEquals(401, e.status());
    }

    @Test
    void status400CarriesServerMessage() {
        server.reply(400, "{\"error\":\"invalid host: a b\"}");
        ApiException e = fails(() -> client.startJob(JobRequest.ofHosts(List.of("a b"))));
        assertEquals(400, e.status());
        assertEquals("invalid host: a b", e.serverMessage());
    }

    @Test
    void status429CarriesRetryAfter() {
        server.reply(429, "{\"error\":\"rate limit\"}", "Retry-After", "7");
        ApiException e = fails(() -> client.meta());
        assertEquals(429, e.status());
        assertEquals(Duration.ofSeconds(7), e.retryAfter().orElseThrow());
    }

    @Test
    void oddRetryAfterIsIgnored() {
        server.reply(429, "{}", "Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT");
        assertTrue(fails(() -> client.meta()).retryAfter().isEmpty());
    }

    @Test
    void pollOfUnknownJobIsHttp404() {
        server.reply(404, "{\"error\":\"job not found or expired\"}");
        ApiException e = fails(() -> client.poll("gone", 0));
        assertEquals(ApiException.Kind.HTTP, e.kind());
        assertEquals(404, e.status());
        assertEquals("job not found or expired", e.serverMessage());
    }

    @Test
    void status502IsHttp502() {
        server.reply(502, "<html><body>Bad gateway</body></html>");
        ApiException e = fails(() -> client.meta());
        assertEquals(502, e.status());
        assertNull(e.serverMessage());
    }

    @Test
    void refusedConnectionIsUnreachable() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        RadarClient closed = new RadarClient(ConnectionSettings.of("http://127.0.0.1:" + port), new JdkTransport());
        ApiException e = assertThrows(ApiException.class, closed::meta);
        assertEquals(ApiException.Kind.UNREACHABLE, e.kind());
        assertEquals(0, e.status());
    }

    @Test
    void closedWithoutAnswerIsUnreachable() {
        server.dropConnections();
        assertEquals(ApiException.Kind.UNREACHABLE, fails(() -> client.meta()).kind());
    }

    @Test
    void redirectIsNotFollowed() throws Exception {
        try (FakeServer other = FakeServer.start()) {
            other.reply(200, ResponsesTest.META);
            server.reply(302, "", "Location", other.uri() + "/api/v1/meta");
            ApiException e = fails(() -> client.meta());
            assertEquals(ApiException.Kind.HTTP, e.kind());
            assertEquals(302, e.status());
            assertTrue(other.requests().isEmpty());
        }
    }

    @Test
    void malformedBodyIsMalformed() {
        server.reply(200, "{");
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.meta()).kind());
    }

    @Test
    void oversizedBodyIsMalformed() {
        // Valid JSON, so only the size cap can refuse it.
        String meta = ResponsesTest.META.strip();
        String body = meta + " ".repeat(Transport.MAX_BODY + 1 - meta.length());
        server.reply(200, body);
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.meta()).kind());
    }

    @Test
    void serverMessageIsOneLine() {
        server.reply(400, "{\"error\":\"a\\nb\"}");
        assertEquals("a b", fails(() -> client.meta()).serverMessage());
    }

    @Test
    void deleteAcceptsGone() throws Exception {
        server.reply(404, "{\"error\":\"job not found or expired\"}").reply(204, "");
        client.deleteJob("j1", Duration.ofSeconds(2));
        client.deleteJob("j1", Duration.ofSeconds(2));
        assertEquals("DELETE", server.requests().get(0).method());
        assertEquals("/api/v1/jobs/j1", server.requests().get(0).path());
    }

    @Test
    void deleteReportsOtherFailures() {
        server.reply(500, "oops");
        assertEquals(500, fails(() -> client.deleteJob("j1", Duration.ofSeconds(2))).status());
    }

    @Test
    void timeoutsMatchThePlan() throws Exception {
        List<String> calls = new ArrayList<>();
        Transport recording = (method, url, headers, body, timeout) -> {
            calls.add(method + " " + url.getPath() + " " + timeout.toSeconds());
            String answer = switch (url.getPath()) {
                case "/api/v1/meta" -> ResponsesTest.META;
                case "/api/v1/subdomains" -> ResponsesTest.SUBDOMAINS;
                case "/api/v1/jobs" -> "{\"job_id\":\"j1\"}";
                default -> ResponsesTest.PAGE;
            };
            return new Reply(method.equals("DELETE") ? 204 : 200, Map.of(), method.equals("DELETE") ? "" : answer);
        };
        RadarClient c = new RadarClient(ConnectionSettings.of("https://scan.hirdman.pro"), recording);
        c.meta();
        c.subdomains("example.com", false);
        c.startJob(JobRequest.ofDomain("example.com", false));
        c.poll("j1", 0);
        c.deleteJob("j1", Duration.ofSeconds(2));
        assertEquals(List.of("GET /api/v1/meta 15", "GET /api/v1/subdomains 75", "POST /api/v1/jobs 30",
                "GET /api/v1/jobs/j1 30", "DELETE /api/v1/jobs/j1 2"), calls);
    }

    @Test
    void anAnswerTheTransportRefusedAsTooLargeIsMalformed() {
        RadarClient c = new RadarClient(ConnectionSettings.of(server.uri().toString()), (m, u, h, b, t) -> {
            throw new Transport.TooLarge();
        });
        ApiException e = fails(() -> c.meta());
        assertEquals(ApiException.Kind.MALFORMED, e.kind());
    }

    @Test
    void theAnswerCapIsEightMegabytes() {
        assertEquals(8 * 1024 * 1024, Transport.MAX_BODY);
        assertEquals("answer larger than 8 MB", new Transport.TooLarge().getMessage());
    }

    @Test
    void lenientJsonIsMalformed() {
        // Unquoted names, NaN, single quotes, comments and trailing data are not JSON.
        for (String body : new String[] {
                "{api_version:1,\"limits\":{\"max_hosts\":50,\"hosts_per_sec\":1.5}}",
                "{\"api_version\":1,\"limits\":{\"max_hosts\":50,\"hosts_per_sec\":NaN}}",
                "{'api_version':1,\"limits\":{\"max_hosts\":50,\"hosts_per_sec\":1.5}}",
                "{\"api_version\":1,/* c */\"limits\":{\"max_hosts\":50,\"hosts_per_sec\":1.5}}",
                "{\"api_version\":1,\"limits\":{\"max_hosts\":50,\"hosts_per_sec\":1.5}} {}"}) {
            server.reply(200, body);
            assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.meta()).kind(), body);
        }
        server.reply(202, "{job_id:j1}");
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.startJob(JobRequest.ofDomain("a.com", false))).kind());
    }

    static String meta(String maxHosts, String hostsPerSec) {
        return "{\"api_version\":1,\"limits\":{\"max_hosts\":" + maxHosts + ",\"hosts_per_sec\":" + hostsPerSec
                + ",\"hosts_per_hour\":300}}";
    }

    @Test
    void metaLimitsOutOfRangeAreMalformed() throws Exception {
        for (String[] bad : new String[][] {{"401", "1.5"}, {"-1", "1.5"}, {"50", "0"}, {"50", "-2"}, {"50", "1e400"}}) {
            server.reply(200, meta(bad[0], bad[1]));
            assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.meta()).kind(), String.join(" ", bad));
        }
        server.reply(200, meta("400", "3")).reply(200, meta("1", "0.5"));
        assertEquals(400, client.meta().limits().maxHosts());
        assertEquals(1, client.meta().limits().maxHosts());
    }

    @Test
    void moreThanFiveThousandSubdomainsAreMalformed() throws Exception {
        server.reply(200, subdomains(RadarClient.MAX_SUBDOMAINS + 1)).reply(200, subdomains(RadarClient.MAX_SUBDOMAINS));
        assertEquals(ApiException.Kind.MALFORMED, fails(() -> client.subdomains("example.com", false)).kind());
        assertEquals(RadarClient.MAX_SUBDOMAINS, client.subdomains("example.com", false).subdomains().size());
    }

    static String subdomains(int n) {
        StringBuilder b = new StringBuilder("{\"domain\":\"example.com\",\"subdomains\":[");
        for (int i = 0; i < n; i++) {
            b.append(i == 0 ? "" : ",").append("{\"host\":\"h").append(i).append(".example.com\",\"priority\":1}");
        }
        return b.append("]}").toString();
    }

    @Test
    void aRequestBurpAlteredIsBlocked() {
        String why = "Burp added credentials to the radar request (Cookie). Exclude the radar server from session handling rules.";
        RadarClient c = new RadarClient(ConnectionSettings.of("https://scan.hirdman.pro"), (m, u, h, b, t) -> {
            throw new Transport.Altered(why);
        });
        ApiException e = fails(() -> c.meta());
        assertTrue(e.blocked());
        assertEquals(why, e.getMessage());
        assertFalse(fails(() -> client.poll("bad id", 0)).blocked());
    }
}
