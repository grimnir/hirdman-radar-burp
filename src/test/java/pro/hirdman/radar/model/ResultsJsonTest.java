package pro.hirdman.radar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;

class ResultsJsonTest {

    static ResultStore sample() {
        ResultStore s = new ResultStore();
        s.apply("example.com", ResultStoreTest.check("vpn.example.com", true, 12, ResultStoreTest.finding("stealer_logs", "high"),
                ResultStoreTest.finding("breached_db_records", "low")), ResultStoreTest.T1);
        s.apply("example.com", ResultStoreTest.check("a.example.com", null, 0), ResultStoreTest.T2);
        s.found("example.com", List.of("blog.example.com"));
        s.apply("other.org", ResultStoreTest.check("x.other.org", true, 0), ResultStoreTest.T2);
        s.apply("example.com", new Check(false, "mail.example.com", 1, 0, 0, 0, 0, true,
                List.of(ResultStoreTest.finding("work_accounts", "high")),
                List.of(ResultStoreTest.src("Collection #1", "2019-01", 2), ResultStoreTest.src("Stealer Logs", null, 1))), ResultStoreTest.T2);
        return s;
    }

    @Test
    void jsonRoundTrip() {
        ResultStore s = sample();
        List<String> errors = new ArrayList<>();
        ResultStore back = ResultsJson.read(ResultsJson.write(s), errors::add);
        assertEquals(s.all(), back.all());
        assertEquals(s.domains(), back.domains());
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void loginPagesAreSavedAndCheckedOnLoad() {
        List<String> errors = new ArrayList<>();
        ResultStore s = new ResultStore();
        s.found("example.com", List.of("a.example.com", "b.example.com", "c.example.com"));
        s.apply("example.com", new Check(false, "c.example.com", 0, 0, 0, 0, 1, true, List.of()), java.time.Instant.EPOCH);
        LoginPage vpn = new LoginPage(LoginPage.Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login");
        s.noteLogin("a.example.com", vpn);
        s.noteLogin("c.example.com", vpn);
        String json = ResultsJson.write(s);
        assertEquals(vpn, ResultsJson.read(json, errors::add).host("a.example.com").orElseThrow().login());
        assertEquals(vpn, ResultsJson.read(json, errors::add).host("c.example.com").orElseThrow().login());
        assertNull(ResultsJson.read(json, errors::add).host("b.example.com").orElseThrow().login());
        String forged = json.replace("FortiGate SSL VPN", "<img src=x>");
        assertNull(ResultsJson.read(forged, errors::add).host("a.example.com").orElseThrow().login());
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void emptyOrMissingLoadsEmptyQuietly() {
        List<String> errors = new ArrayList<>();
        assertTrue(ResultsJson.read(null, errors::add).all().isEmpty());
        assertTrue(ResultsJson.read("", errors::add).all().isEmpty());
        assertTrue(errors.isEmpty());
    }

    @Test
    void corruptedJsonLoadsEmpty() {
        for (String bad : new String[] {"{", "[]", "\"x\"", "{\"hosts\":[]}", "{\"v\":1,\"hosts\":5}"}) {
            List<String> errors = new ArrayList<>();
            assertTrue(ResultsJson.read(bad, errors::add).all().isEmpty(), bad);
            assertEquals(List.of("Hirdman Radar: saved results could not be read, starting empty"), errors, bad);
        }
    }

    @Test
    void newerFormatLoadsEmpty() {
        List<String> errors = new ArrayList<>();
        assertTrue(ResultsJson.read("{\"v\":3}", errors::add).all().isEmpty());
        assertEquals(List.of("Hirdman Radar: saved results are from a newer plugin, starting empty"), errors);
    }

    @Test
    void badRowsAreSkippedAndReported() {
        String json = """
                {"v":1,"hosts":[
                  {"host":"ok.example.com","domain":"example.com","status":"CLEAN"},
                  {"host":"<img src=x>.example.com","domain":"example.com","status":"CLEAN"},
                  {"host":"b.example.com","domain":"example.com","status":"PWNED"},
                  {"host":"c.example.com","domain":"<b>","status":"CLEAN"},
                  {"host":"d.example.com","domain":"example.com","status":"CHECKED","stealer":-5,"checked_at":"not a time"},
                  7
                ]}
                """;
        List<String> errors = new ArrayList<>();
        ResultStore s = ResultsJson.read(json, errors::add);
        assertEquals(List.of("ok.example.com", "d.example.com"), s.all().stream().map(HostResult::host).toList());
        HostResult d = s.host("d.example.com").orElseThrow();
        assertEquals(0, d.stealer());
        assertEquals(null, d.checkedAt());
        assertEquals(List.of("Hirdman Radar: skipped 4 saved rows that could not be read"), errors);
    }

    @Test
    void savedDataOverTheSizeLimitIsNotParsed() {
        List<String> errors = new ArrayList<>();
        String json = ResultsJson.write(sample());
        ResultStore s = new ResultStore();
        ResultsJson.readInto(s, json, errors::add, json.length() - 1, 100);
        assertTrue(s.all().isEmpty());
        assertEquals(List.of("Hirdman Radar: saved results are too large to load (" + json.length() + " characters), starting empty"),
                errors);
    }

    @Test
    void rowsPastTheLimitAreNotLoaded() {
        List<String> errors = new ArrayList<>();
        ResultStore s = new ResultStore();
        s.found("example.org", List.of("www.example.org"));
        ResultsJson.readInto(s, ResultsJson.write(sample()), errors::add, Integer.MAX_VALUE, 3);
        assertEquals(3, s.all().size());
        assertEquals(List.of("Hirdman Radar: the project holds more saved rows than the plugin loads (3), the rest were left out"),
                errors);
    }

    @Test
    void aRowWithAnOverlongTextIsSkipped() {
        String name = "n".repeat(ResultsJson.MAX_STRING + 1);
        String json = "{\"v\":2,\"hosts\":[{\"host\":\"a.example.com\",\"domain\":\"example.com\",\"status\":\"CHECKED\","
                + "\"findings\":[{\"kind\":\"k\",\"severity\":\"high\",\"name\":\"" + name + "\"}]},"
                + "{\"host\":\"b.example.com\",\"domain\":\"example.com\",\"status\":\"CLEAN\"}],"
                + "\"texts\":[\"" + name + "\"]}";
        List<String> errors = new ArrayList<>();
        ResultStore s = ResultsJson.read(json, errors::add);
        assertEquals(List.of("b.example.com"), s.all().stream().map(HostResult::host).toList());
        assertEquals(List.of("Hirdman Radar: skipped 1 saved rows that could not be read"), errors);
    }

    @Test
    void writesTheGivenRowsOnly() {
        ResultStore s = sample();
        ResultStore back = ResultsJson.read(ResultsJson.write(s.domain("other.org")), e -> { });
        assertEquals(s.domain("other.org"), back.all());
    }

    @Test
    void oddVersionNumbersAreUnreadable() {
        for (String v : List.of("1e99999", "1.9", "4294967297", "-1", "1E0")) {
            List<String> errors = new ArrayList<>();
            ResultStore store = ResultsJson.read("{\"v\":" + v + ",\"hosts\":[]}", errors::add);
            assertTrue(store.all().isEmpty(), v);
            assertEquals(List.of("Hirdman Radar: saved results could not be read, starting empty"), errors, v);
        }
    }

    @Test
    void textsEveryFindingOfAKindRepeatsAreSavedOnce() {
        String background = "<p>" + "Why this matters. ".repeat(40) + "</p>";
        String remediation = "<p>" + "What to do. ".repeat(20) + "</p>";
        ResultStore s = new ResultStore();
        for (String host : List.of("a.example.com", "b.example.com", "c.example.com")) {
            Finding f = new Finding("stealer_logs", "high", "tentative", "Stealer", "<p>" + host + "</p>", background, remediation);
            s.apply("example.com", new Check(false, host, 0, 0, 0, 0, 1, true, List.of(f)), ResultStoreTest.T1);
        }
        String json = ResultsJson.write(s);
        assertTrue(json.contains("\"v\":2"), json);
        assertEquals(1, json.split(java.util.regex.Pattern.quote(background), -1).length - 1);
        assertEquals(1, json.split(java.util.regex.Pattern.quote(remediation), -1).length - 1);
        List<String> errors = new ArrayList<>();
        assertEquals(s.all(), ResultsJson.read(json, errors::add).all());
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void resultsSavedByTheFirstFormatStillLoad() {
        String json = """
                {"v":1,"hosts":[{"host":"vpn.example.com","domain":"example.com","status":"CHECKED","stealer":2,
                  "findings":[{"kind":"stealer_logs","severity":"high","confidence":"tentative","name":"N",
                    "detail":"<p>d</p>","background":"<p>b</p>","remediation":"<p>r</p>"}],
                  "checked_at":"2026-11-17T10:00:00Z"}]}
                """;
        List<String> errors = new ArrayList<>();
        HostResult r = ResultsJson.read(json, errors::add).host("vpn.example.com").orElseThrow();
        assertEquals(List.of(new Finding("stealer_logs", "high", "tentative", "N", "<p>d</p>", "<p>b</p>", "<p>r</p>")),
                r.findings());
        assertEquals(2, r.stealer());
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void aTextNumberOutsideTheTableLoadsAsNoText() {
        String json = """
                {"v":2,"texts":["<p>b</p>",5],"hosts":[{"host":"vpn.example.com","domain":"example.com","status":"CHECKED",
                  "findings":[{"kind":"stealer_logs","name":"N","background":0,"remediation":2},
                              {"kind":"work_accounts","name":"W","background":1,"remediation":1.5},
                              {"kind":"personal_accounts","name":"P","background":-1,"remediation":{}}]}]}
                """;
        List<String> errors = new ArrayList<>();
        List<Finding> fs = ResultsJson.read(json, errors::add).host("vpn.example.com").orElseThrow().findings();
        assertEquals("<p>b</p>", fs.get(0).background());
        assertNull(fs.get(0).remediation());
        for (Finding f : fs.subList(1, 3)) {
            assertNull(f.background(), f.kind());
            assertNull(f.remediation(), f.kind());
        }
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void breachSourcesAreSaved() {
        String json = ResultsJson.write(sample());
        assertTrue(json.contains("\"sources\":[{\"name\":\"Collection #1\",\"date\":\"2019-01\",\"count\":2}"), json);
        HostResult back = ResultsJson.read(json, e -> { }).host("mail.example.com").orElseThrow();
        assertEquals("2019-01", back.latestBreach());
    }

    @Test
    void aRowOutsideItsDomainIsSkippedAndACheckTimeInTheFutureIsDropped() {
        String json = """
                {"v":1,"hosts":[
                  {"host":"x.other.org","domain":"example.com","status":"CLEAN"},
                  {"host":"example.com.evil.org","domain":"example.com","status":"CLEAN"},
                  {"host":"a.example.com","domain":"example.com","status":"CLEAN","checked_at":"2999-01-01T00:00:00Z"},
                  {"host":"b.example.com","domain":"example.com","status":"CLEAN","checked_at":"2020-01-01T00:00:00Z"},
                  {"host":"example.com","domain":"example.com","status":"CLEAN","checked_at":"%s"}
                ]}
                """.formatted(Instant.now().plus(Duration.ofHours(1)));
        List<String> errors = new ArrayList<>();
        ResultStore s = ResultsJson.read(json, errors::add);
        assertEquals(List.of("a.example.com", "b.example.com", "example.com"), s.all().stream().map(HostResult::host).toList());
        assertNull(s.host("a.example.com").orElseThrow().checkedAt());
        assertEquals(Instant.parse("2020-01-01T00:00:00Z"), s.host("b.example.com").orElseThrow().checkedAt());
        // A clock a little ahead is no reason to forget the check.
        assertTrue(s.host("example.com").orElseThrow().checkedAt() != null);
        assertEquals(List.of("Hirdman Radar: skipped 2 saved rows that could not be read"), errors);
    }
}
