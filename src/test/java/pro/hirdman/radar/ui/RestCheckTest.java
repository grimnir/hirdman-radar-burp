package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.model.ResultStore;

class RestCheckTest {

    final ResultStore store = new ResultStore();

    void checked(String host, boolean ok) {
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 0, ok, List.of()), Instant.EPOCH);
    }

    RestCheck of(int n) {
        return new RestCheck("example.com", IntStream.range(0, n).mapToObj(i -> "h" + i + ".example.com").toList());
    }

    @Test
    void onlyForADomainThatWasCheckedAndHasFoundSubdomains() {
        store.found("example.com", List.of("a.example.com", "b.example.com"));
        assertTrue(RestCheck.of("example.com", store.domain("example.com")).isEmpty());
        checked("example.com", false);
        assertTrue(RestCheck.of("example.com", store.domain("example.com")).isEmpty());
        checked("example.com", true);
        checked("b.example.com", true);
        RestCheck r = RestCheck.of("example.com", store.domain("example.com")).orElseThrow();
        assertEquals(List.of("a.example.com"), r.hosts());
        assertEquals("1 subdomain of example.com is not checked yet.", r.line());
        checked("a.example.com", false);
        assertTrue(RestCheck.of("example.com", store.domain("example.com")).isEmpty());
        assertTrue(RestCheck.of(null, List.of()).isEmpty());
    }

    @Test
    void theQuestionSaysHowLongTheHourlyLimitMakesIt() {
        assertEquals("1100 subdomains of example.com are not checked yet.", of(1100).line());
        assertEquals("Check 1100 subdomains of example.com that are not checked yet? Your address can check 120 more hosts"
                + " this hour and 300 an hour after that, so this takes about 4 h; keep Burp open.",
                of(1100).question(new Meta.Limits(50, 1.5, 300, 120)));
        assertEquals("Check 60 subdomains of example.com that are not checked yet? Your address can check 120 more hosts"
                + " this hour.", of(60).question(new Meta.Limits(50, 1.5, 300, 120)));
        assertEquals("Check 60 subdomains of example.com that are not checked yet? Your address can check 0 more hosts"
                + " this hour and 300 an hour after that, so this takes about 1 h; keep Burp open.",
                of(60).question(new Meta.Limits(50, 1.5, 300, 0)));
        assertEquals("Check 1100 subdomains of example.com that are not checked yet?",
                of(1100).question(new Meta.Limits(400, 1.5, 0)));
        assertEquals("Check 1100 subdomains of example.com that are not checked yet?", of(1100).question(null));
        // No allowance reported, or no hourly limit: nothing to estimate.
        assertEquals("Check 1100 subdomains of example.com that are not checked yet?",
                of(1100).question(new Meta.Limits(50, 1.5, 300)));
        assertEquals("Check 1100 subdomains of example.com that are not checked yet?",
                of(1100).question(new Meta.Limits(400, 1.5, 0, 0)));
        assertEquals("Check 120 subdomains of example.com that are not checked yet? Your address can check 120 more hosts"
                + " this hour.", of(120).question(new Meta.Limits(50, 1.5, 300, 120)));
        assertEquals("Check 700 subdomains of example.com that are not checked yet? Your address can check 120 more hosts"
                + " this hour and 300 an hour after that, so this takes about 2 h; keep Burp open.",
                of(700).question(new Meta.Limits(50, 1.5, 300, 120)));
    }
}
