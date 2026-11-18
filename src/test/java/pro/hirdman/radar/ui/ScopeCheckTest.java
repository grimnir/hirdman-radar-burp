package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ScopeCheckTest {

    static final Instant NOW = Instant.parse("2026-11-17T12:00:00Z");

    static ScopeCheck plan(List<String> hosts, Map<String, Instant> checked) {
        return ScopeCheck.plan(hosts, "radar.example.com", h -> Optional.ofNullable(checked.get(h)), NOW);
    }

    @Test
    void skipsIpsBadNamesTheServerAndHostsCheckedInTheLastDay() {
        ScopeCheck c = plan(List.of("a.example.com", "A.example.com", "10.0.0.1", "radar.example.com", "old.example.com",
                "new.example.com", "bad_host!"), Map.of("old.example.com", NOW.minus(Duration.ofHours(25)),
                "new.example.com", NOW.minus(Duration.ofHours(2))));
        assertEquals(List.of("a.example.com", "old.example.com"), c.hosts());
        assertEquals(1, c.recent());
    }

    @Test
    void theQuestionGivesTheCountsAndWhatTheHourAllows() {
        ScopeCheck two = new ScopeCheck(List.of("a.example.com", "b.example.com"), 1);
        assertEquals("Check 2 in-scope hosts from the site map for leaks? 1 host checked in the last 24 h is skipped.",
                two.question(null));
        assertEquals("Check 2 in-scope hosts from the site map for leaks? 1 host checked in the last 24 h is skipped. "
                + "Your address can check 300 more hosts this hour.", two.question(300));
        assertTrue(two.question(2).endsWith("Your address can check 2 more hosts this hour."), two.question(2));
        assertEquals("Check 2 in-scope hosts from the site map for leaks? 1 host checked in the last 24 h is skipped. "
                + "Your address can check 1 more host this hour; the rest continue when the limit refills.", two.question(1));
        assertEquals("Check 1 in-scope host from the site map for leaks? 3 hosts checked in the last 24 h are skipped.",
                new ScopeCheck(List.of("a.example.com"), 3).question(null));
        assertEquals("Check 1 in-scope host from the site map for leaks?", new ScopeCheck(List.of("a.example.com"), 0).question(null));
    }

    @Test
    void nothingToCheckSaysWhy() {
        assertTrue(new ScopeCheck(List.of(), 0).isEmpty());
        assertEquals("No in-scope host names in the site map.", new ScopeCheck(List.of(), 0).nothing());
        assertEquals("Nothing to check: 1 in-scope host was checked in the last 24 h.", new ScopeCheck(List.of(), 1).nothing());
        assertEquals("Nothing to check: 4 in-scope hosts were checked in the last 24 h.", new ScopeCheck(List.of(), 4).nothing());
    }
}
