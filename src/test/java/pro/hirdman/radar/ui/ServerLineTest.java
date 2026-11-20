package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Reply;

class ServerLineTest {

    static Meta meta(String minVersion, int perHour, String countsOnly) {
        return new Meta(1, minVersion, "anonymous", new Meta.Limits(50, 1.5, perHour), new Meta.Notes("db", "cov", countsOnly));
    }

    @Test
    void passedShowsTheLimits() {
        ServerLine l = ServerLine.passed(meta("0.1.0", 300, "x"), "0.1.0");
        assertEquals("Without a key: up to 50 hosts per check and 300 hosts per hour from your address.", l.text());
        assertFalse(l.tryAgain());
        assertEquals("", ServerLine.passed(meta(null, 0, "x"), "0.1.0").text());
    }

    @Test
    void olderPluginIsTold() {
        ServerLine l = ServerLine.passed(meta("0.2.0", 300, "x"), "0.1.0");
        assertEquals("This plugin is older than the server expects (0.2.0). Download the new version from the releases page "
                + "or the BApp Store.", l.text());
        assertFalse(l.tryAgain());
        assertEquals("Releases page", l.linkText());
        assertEquals(ServerLine.RELEASES, l.linkUrl());
        assertEquals("https://github.com/grimnir/hirdman-radar-burp/releases/latest", ServerLine.RELEASES);
    }

    static Meta release(String latest, String url, String announcement) {
        return new Meta(1, "0.1.0", "anonymous", new Meta.Limits(50, 1.5, 0), new Meta.Notes("db", "cov", "c", announcement),
                latest, url);
    }

    @Test
    void aNewerReleaseIsOfferedQuietly() {
        ServerLine l = ServerLine.passed(release("0.2.0", "https://example.org/r", null), "0.1.0");
        assertEquals("", l.text());
        assertEquals("Hirdman Radar 0.2.0 is available", l.linkText());
        assertEquals("https://example.org/r", l.linkUrl());
        assertEquals(ServerLine.RELEASES, ServerLine.passed(release("0.2.0", null, null), "0.1.0").linkUrl());
        // Only an https page opens in the browser.
        assertEquals(ServerLine.RELEASES, ServerLine.passed(release("0.2.0", "javascript:alert(1)", null), "0.1.0").linkUrl());
        assertEquals(ServerLine.RELEASES, ServerLine.passed(release("0.2.0", "http://example.org/r", null), "0.1.0").linkUrl());
        assertEquals("https://hirdman.pro/radar?utm_source=burp&utm_medium=plugin&utm_content=footer",
                ServerLine.passed(release("0.2.0", "https://hirdman.pro/radar", null), "0.1.0").linkUrl());
        for (String same : new String[] {"0.1.0", "0.0.9", null, "x"}) {
            ServerLine none = ServerLine.passed(release(same, "https://example.org/r", null), "0.1.0");
            assertEquals(null, none.linkText(), same);
            assertEquals(null, none.linkUrl(), same);
        }
    }

    @Test
    void theAnnouncementIsOneLineAfterTheLimits() {
        ServerLine l = ServerLine.passed(new Meta(1, null, "anonymous", new Meta.Limits(50, 1.5, 300),
                new Meta.Notes("db", "cov", "c", "Maintenance\non Sunday."), null, null), "0.1.0");
        assertTrue(l.text().endsWith(" Maintenance on Sunday."), l.text());
        assertEquals("", ServerLine.passed(release(null, null, " "), "0.1.0").text());
    }

    @Test
    void anotherServerIsNamed() {
        assertEquals("Server: radar.example.org.", ServerLine.passed(release(null, null, null), "0.1.0", "radar.example.org").text());
        assertEquals("", ServerLine.passed(release(null, null, null), "0.1.0", "scan.hirdman.pro").text());
    }

    @Test
    void serverVersionTextIsOneShortLine() {
        String l = ServerLine.passed(meta("9.\n9.9-" + "x".repeat(100), 300, "x"), "0.1.0").text();
        assertTrue(l.startsWith("This plugin is older than the server expects (9. 9.9-" + "x".repeat(13) + "). Download"), l);
    }

    @Test
    void unreachableOffersTryAgain() {
        ServerLine l = ServerLine.failed(ApiException.unreachable(new IOException("refused")), "scan.hirdman.pro");
        assertEquals("Cannot reach scan.hirdman.pro. The plugin needs internet access, directly or through Burp's upstream proxy. Behind a proxy that re-signs HTTPS, turn off the certificate check in Settings > Extensions > Hirdman Radar.",
                l.text());
        assertTrue(l.tryAgain());
    }

    @Test
    void otherFailuresNameTheStatus() {
        ServerLine http = ServerLine.failed(ApiException.http(new Reply(502, Map.of(), "")), "h");
        assertEquals("Cannot connect to the radar server: HTTP 502.", http.text());
        assertTrue(http.tryAgain());
        assertEquals("The radar server sent an unexpected answer.",
                ServerLine.failed(ApiException.malformed("bad", null), "h").text());
    }

    @Test
    void badUrlShowsTheProblem() {
        ServerLine l = ServerLine.badUrl("Server URL must start with https://");
        assertEquals("Server URL must start with https://", l.text());
        assertFalse(l.tryAgain());
        assertEquals("", ServerLine.NONE.text());
    }

    @Test
    void footerUsesTheServerNote() {
        assertEquals("Counts only: no accounts, passwords, raw records or dumps. Partial check, about a third of a full HIRDMAN review.",
                ServerLine.footer(null));
        assertEquals("Only counts\nhere. Partial check, about a third of a full HIRDMAN review.".replace("\n", " "),
                ServerLine.footer(meta(null, 0, "Only counts\nhere.")));
        assertEquals(ServerLine.footer(null), ServerLine.footer(meta(null, 0, " ")));
    }
}
