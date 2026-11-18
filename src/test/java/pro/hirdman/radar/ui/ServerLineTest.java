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
        assertEquals("This plugin is older than the server expects (0.2.0). Update it from the BApp Store.", l.text());
        assertFalse(l.tryAgain());
    }

    @Test
    void serverVersionTextIsOneShortLine() {
        String l = ServerLine.passed(meta("9.\n9.9-" + "x".repeat(100), 300, "x"), "0.1.0").text();
        assertEquals("This plugin is older than the server expects (9. 9.9-" + "x".repeat(13) + "). Update it from the BApp Store.", l);
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
        assertEquals("Server check failed: HTTP 502.", http.text());
        assertTrue(http.tryAgain());
        assertEquals("Server check failed: unexpected answer.",
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
