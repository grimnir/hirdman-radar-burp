package pro.hirdman.radar.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.Risk;

class OptionsTest {

    @Test
    void serverHostIsTheServerUrlHostOrNull() {
        Options d = Options.defaults();
        assertEquals("scan.hirdman.pro", d.serverHost());
        assertEquals("radar.example.com", new Options("https://Radar.example.com:8443/", true, true, Risk.LOW, true, false, true, 5,
                false).serverHost());
        assertNull(new Options("http://radar.example.com", true, true, Risk.LOW, true, false, true, 5, false).serverHost());
    }

    @Test
    void theRadarIsOnUnlessTheProjectTurnsItOff() {
        assertEquals(false, Options.defaults().offForProject());
        Options d = Options.defaults();
        assertEquals(true, new Options(d.serverUrl(), d.autoIssues(), d.includeOutOfScope(), d.lowest(), d.addToSiteMap(),
                d.watchTraffic(), d.recheckNotChecked(), d.attempts(), d.alwaysRescan(), true).offForProject());
    }

    static Options withServer(String url) {
        Options d = Options.defaults();
        return new Options(url, d.autoIssues(), d.includeOutOfScope(), d.lowest(), d.addToSiteMap(), d.watchTraffic(),
                d.recheckNotChecked(), d.attempts(), d.alwaysRescan());
    }

    static Options withAttempts(int attempts) {
        return new Options("https://scan.hirdman.pro", true, false, Risk.LOW, true, false, true, attempts, false);
    }

    @Test
    void issueOptionsComeFromTheSettings() {
        assertEquals(new pro.hirdman.radar.issues.IssueOptions(false, true, Risk.MEDIUM, "https://scan.hirdman.pro"),
                new Options("https://scan.hirdman.pro/", false, true, Risk.MEDIUM, true, false, true, 5, false).issueOptions());
    }

    @Test
    void anUnusableServerUrlGivesIssuesNoLink() {
        assertEquals(null, new Options("ftp://scan.hirdman.pro", true, true, Risk.LOW, true, false, true, 5, false).issueOptions()
                .site());
    }

    @Test
    void aPrivateProjectGivesIssuesAndExportsNoLink() {
        // A link with ?domain= would send the target to the radar when clicked in a report.
        assertEquals(null, new Options("https://scan.hirdman.pro", true, true, Risk.LOW, true, false, true, 5, false, true).issueOptions()
                .site());
    }

    @Test
    void defaultsMatchSpec() {
        // Out-of-scope hosts get issues too: a check the user asked for should show up in Issues.
        assertEquals(new Options("https://scan.hirdman.pro", true, true, Risk.LOW, true, false, true, 5, false), Options.defaults());
        assertEquals(Optional.empty(), Options.defaults().serverUrlProblem());
    }

    @Test
    void badServerUrlIsReported() {
        assertEquals(Optional.of("Server URL must start with https://"), withServer("http://scan.hirdman.pro").serverUrlProblem());
        assertEquals(Optional.of("Server URL is not valid"), withServer("").serverUrlProblem());
        assertEquals(Optional.of("Server URL is not valid"), withServer(null).serverUrlProblem());
    }

    @Test
    void attemptsAreClamped() {
        assertEquals(1, withAttempts(0).attempts());
        assertEquals(1, withAttempts(-3).attempts());
        assertEquals(10, withAttempts(50).attempts());
        assertEquals(7, withAttempts(7).attempts());
    }

    @Test
    void missingLowestMeansLow() {
        assertEquals(Risk.LOW, new Options("https://scan.hirdman.pro", true, false, null, true, false, true, 5, false).lowest());
    }
}
