package pro.hirdman.radar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.LoginPage.Kind;

class LoginPageTest {

    final AtomicInteger bodyReads = new AtomicInteger();

    Optional<LoginPage> detect(String path, int status, String auth, boolean passwordField) {
        return LoginPage.detect(path, status, auth, () -> {
            bodyReads.incrementAndGet();
            return passwordField;
        });
    }

    @Test
    void knownPathsNameTheProduct() {
        assertEquals(Optional.of(new LoginPage(Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login")),
                detect("/remote/login", 200, null, true));
        assertEquals("Outlook on the web", detect("/OWA/auth/logon.aspx", 302, null, false).orElseThrow().label());
        assertEquals("Outlook on the web", detect("/owa", 401, "NTLM", false).orElseThrow().label());
        assertEquals("Cisco AnyConnect VPN", detect("/+CSCOE+/logon.html", 200, null, false).orElseThrow().label());
        assertEquals(Optional.empty(), detect("/owasp/", 302, null, false));
        assertEquals(Optional.empty(), detect("/remote/login", 404, null, false));
        assertEquals(0, bodyReads.get(), "a known path needs no body");
    }

    @Test
    void http401NamesTheScheme() {
        assertEquals(Optional.of(new LoginPage(Kind.HTTP_AUTH, "NTLM sign-in", "/")), detect("/", 401, "NTLM", false));
        assertEquals("HTTP Basic sign-in", detect("/x", 401, "Basic realm=\"x\"", false).orElseThrow().label());
        assertEquals("Windows sign-in (Negotiate)", detect("/x", 401, "negotiate", false).orElseThrow().label());
        assertEquals("HTTP Digest sign-in", detect("/x", 401, "Digest realm=\"x\", nonce=\"y\"", false).orElseThrow().label());
        assertEquals(Optional.empty(), detect("/api", 401, "Bearer", false));
        assertEquals(Optional.empty(), detect("/x", 403, "Basic", false));
        assertEquals(0, bodyReads.get());
    }

    @Test
    void aPasswordFieldIsTheWeakestSign() {
        assertEquals(Optional.of(new LoginPage(Kind.PASSWORD_FORM, "Password form", "/login")), detect("/login", 200, null, true));
        assertEquals(Optional.empty(), detect("/login", 200, null, false));
        assertEquals(Optional.empty(), detect("/login", 500, null, true));
        assertTrue(new LoginPage(Kind.KNOWN_PATH, "FortiGate SSL VPN", "/").betterThan(
                new LoginPage(Kind.HTTP_AUTH, "NTLM sign-in", "/")));
        assertTrue(new LoginPage(Kind.PASSWORD_FORM, "Password form", "/").betterThan(null));
        assertFalse(new LoginPage(Kind.PASSWORD_FORM, "Password form", "/").betterThan(
                new LoginPage(Kind.PASSWORD_FORM, "Password form", "/x")));
    }

    @Test
    void onlyTheStartOfThePathIsKeptSoTokensStayOut() {
        assertEquals("/owa/", detect("/OWA/auth/logon.aspx", 302, null, false).orElseThrow().path());
        assertEquals("/owa/", detect("/owa", 401, "NTLM", false).orElseThrow().path());
        assertEquals("/cas/login", detect("/cas/login;jsessionid=ABC", 200, null, false).orElseThrow().path());
        assertEquals("/reset/", detect("/reset/MQ/c3k9xq-8f1e/", 200, null, true).orElseThrow().path());
        assertEquals("/login", detect("/login;jsessionid=ABC", 200, null, true).orElseThrow().path());
        assertEquals("/admin/", detect("/admin/x", 401, "Basic", false).orElseThrow().path());
        assertEquals("/", detect("/a\r\nSet-Cookie: x", 401, "Basic", false).orElseThrow().path());
        assertEquals("/", detect("no-slash", 401, "Basic", false).orElseThrow().path());
    }

    @Test
    void aSegmentWithOddCharactersBecomesTheRoot() {
        // The path goes into issues and reports: encoded tokens and bidi controls stay out.
        assertEquals("/", detect("/%41dmin/x", 200, null, true).orElseThrow().path());
        assertEquals("/", detect("/reset\u202E/x", 200, null, true).orElseThrow().path());
        assertEquals("/", detect("/a b", 401, "Basic", false).orElseThrow().path());
        assertEquals("/", detect("/a\n", 401, "Basic", false).orElseThrow().path());
        assertEquals("/My-App_2.0~x/", detect("/My-App_2.0~x/login", 200, null, true).orElseThrow().path());
        assertEquals("/" + "a".repeat(64), detect("/" + "a".repeat(64), 200, null, true).orElseThrow().path());
        assertEquals("/", detect("/" + "a".repeat(65), 200, null, true).orElseThrow().path());
    }

    @Test
    void longPathsAreCut() {
        for (String path : new String[] {"/" + "a".repeat(300), "/" + "a".repeat(300) + "/x", "/" + "a".repeat(199) + "/x"}) {
            String kept = detect(path, 200, null, true).orElseThrow().path();
            assertEquals("/", kept);
            assertTrue(LoginPage.restore("PASSWORD_FORM", "Password form", kept).isPresent(), kept);
        }
    }

    @Test
    void restoreAcceptsOnlyKnownLabelsAndPlainPaths() {
        assertEquals(Optional.of(new LoginPage(Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login")),
                LoginPage.restore("KNOWN_PATH", "FortiGate SSL VPN", "/remote/login"));
        assertEquals(Optional.empty(), LoginPage.restore("KNOWN_PATH", "<script>", "/"));
        assertEquals(Optional.empty(), LoginPage.restore("WHATEVER", "Password form", "/"));
        assertEquals(Optional.empty(), LoginPage.restore(null, "Password form", "/"));
        assertEquals(Optional.empty(), LoginPage.restore("PASSWORD_FORM", "Password form", "no-slash"));
        assertEquals(Optional.empty(), LoginPage.restore("PASSWORD_FORM", "Password form", "/a\nb"));
        assertEquals(Optional.empty(), LoginPage.restore("PASSWORD_FORM", "Password form", "/a\n"));
        assertEquals(Optional.empty(), LoginPage.restore("PASSWORD_FORM", "Password form", "/%41dmin/"));
        assertEquals(Optional.empty(), LoginPage.restore("PASSWORD_FORM", "Password form", "/" + "a".repeat(300)));
        assertTrue(LoginPage.restore("PASSWORD_FORM", "Password form", "/reset/").isPresent());
        assertEquals(Optional.empty(), LoginPage.restore("PASSWORD_FORM", "Password form", "/reset/MQ/c3k9xq-8f1e/"));
        assertEquals(Optional.empty(), LoginPage.restore("PASSWORD_FORM", "Password form", "/login;jsessionid=ABC"));
        assertEquals(Optional.empty(), LoginPage.restore("KNOWN_PATH", "Outlook on the web", "/owa/auth/logon.aspx"));
    }
}
