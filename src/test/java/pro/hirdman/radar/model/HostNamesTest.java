package pro.hirdman.radar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class HostNamesTest {

    @Test
    void normalizesHosts() {
        assertEquals(Optional.of("vpn.example.com"), HostNames.normalize("  VPN.Example.com. "));
        assertEquals(Optional.of("xn--80ak6aa92e.com"), HostNames.normalize("xn--80ak6aa92e.com"));
        assertEquals(Optional.of("a-1.b2.example.io"), HostNames.normalize("a-1.b2.example.io"));
    }

    @Test
    void rejectsBadHosts() {
        String longHost = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(58) + ".com";
        assertEquals(254, longHost.length());
        for (String bad : new String[] {"10.0.0.1", "::1", "[::1]", "_dmarc.example.com", "a b.example.com",
                "<x>.example.com", "com", "-a.example.com", "a-.example.com", "a..example.com", ".example.com",
                "example.com/x", "user@example.com", "example.com:443", "пример.рф", "", "   ", longHost, null}) {
            assertTrue(HostNames.normalize(bad).isEmpty(), String.valueOf(bad));
        }
    }

    @Test
    void longestValidNameIsAccepted() {
        String host = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(57) + ".com";
        assertEquals(253, host.length());
        assertEquals(Optional.of(host), HostNames.normalize(host));
    }

    @Test
    void internalZonesAndIpsAreNotPublic() {
        for (String internal : new String[] {"srv01.corp.local", "jira.internal", "nas.home.arpa", "x.lan", "app.corp",
                "router.home", "db.localhost", "a.test", "b.invalid", "c.example", "hidden.onion", "wiki.intranet",
                "box.localdomain", "1.0.0.10.in-addr.arpa", "JIRA.Internal.", "10.0.0.1", "::1", "_x.example.com", null}) {
            assertFalse(HostNames.isPublic(internal), String.valueOf(internal));
        }
        for (String pub : new String[] {"a.example.com", "local.example.com", "corp.example.org", "test.example.net",
                "VPN.Example.com."}) {
            assertTrue(HostNames.isPublic(pub), pub);
        }
    }

    @Test
    void domainInputTakesTheNameOutOfWhatWasPasted() {
        assertEquals(Optional.of("example.com"), HostNames.domainInput(" https://User:pw@Example.com:8443/login?x=1#y "));
        assertEquals(Optional.of("example.com"), HostNames.domainInput("*.example.com"));
        assertEquals(Optional.of("example.com"), HostNames.domainInput("example.com."));
        assertEquals(Optional.of("example.com"), HostNames.domainInput("example.com:443"));
        assertEquals(Optional.of("example.com"), HostNames.domainInput("example.com/path"));
        assertEquals(Optional.of("a.example.com"), HostNames.domainInput("ftp://a.example.com"));
        assertEquals(Optional.of("example.com"), HostNames.domainInput("example.com/login?next=https://other.org/"));
        // Browsers read a backslash as a slash, so the name before it is the host, not the one after "@".
        assertEquals(Optional.of("target.example.com"), HostNames.domainInput("https://target.example.com\\@attacker.org/"));
        assertEquals(Optional.of("example.com"), HostNames.domainInput("example.com\\path"));
        // Protocol-relative links from HTML source, and names in national scripts as DNS has them.
        assertEquals(Optional.of("cdn.example.com"), HostNames.domainInput("//cdn.example.com/x.js"));
        assertEquals(Optional.of("xn--e1afmkfd.xn--p1ai"), HostNames.domainInput("пример.рф"));
        assertEquals(Optional.of("xn--e1afmkfd.xn--p1ai"), HostNames.domainInput("https://Пример.РФ/путь"));
        for (String bad : new String[] {"10.0.0.1", "http://10.0.0.1:80/", "[::1]", "http://[::1]/", "http://",
                "*.", "localhost", "a b.example.com", "", null}) {
            assertTrue(HostNames.domainInput(bad).isEmpty(), String.valueOf(bad));
        }
    }
}
