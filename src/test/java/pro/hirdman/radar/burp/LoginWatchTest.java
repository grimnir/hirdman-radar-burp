package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.LoginPage;
import pro.hirdman.radar.model.ResultStore;

class LoginWatchTest {

    final ResultStore store = new ResultStore();
    final LoginWatch watch = new LoginWatch(store);
    final AtomicInteger bodyReads = new AtomicInteger();
    final AtomicInteger regexScans = new AtomicInteger();
    /** The message length Burp reports, when the test needs it larger than the text. */
    Integer length;

    HttpResponseReceived response(String host, String path, int status, String auth, MimeType mime, String body) {
        return response(host, path, status, auth, mime, "HTTP/1.1 " + status + " X\r\n\r\n", body, null);
    }

    HttpResponseReceived response(String host, String path, int status, String auth, MimeType mime, String head, String body,
            String contentLength) {
        String message = head + body;
        HttpService service = fake(HttpService.class, Map.of("host", host));
        HttpRequest request = fake(HttpRequest.class, Map.of("httpService", service, "pathWithoutQuery", path));
        ByteArray bytes = fake(ByteArray.class, (m, a) -> switch (m) {
            case "length" -> length != null ? length : message.length();
            case "indexOf" -> {
                int from = (Integer) a[a.length - 2];
                int to = Math.min((Integer) a[a.length - 1], message.length());
                if (a[0] instanceof Pattern pattern) {
                    regexScans.incrementAndGet();
                    Matcher matcher = pattern.matcher(message).region(from, to);
                    yield matcher.find() ? matcher.start() : -1;
                }
                assertEquals(Boolean.FALSE, a[1], "the word is looked for in any case");
                int at = message.substring(from, to).toLowerCase(Locale.ROOT).indexOf(((String) a[0]).toLowerCase(Locale.ROOT));
                yield at < 0 ? -1 : from + at;
            }
            default -> Fakes.DEFAULT;
        });
        Map<String, Object> answers = new HashMap<>(Map.of("initiatingRequest", request, "statusCode", (short) status,
                "mimeType", mime, "bodyOffset", head.length()));
        return fake(HttpResponseReceived.class, (m, a) -> switch (m) {
            case "headerValue" -> "WWW-Authenticate".equalsIgnoreCase((String) a[0]) ? auth
                    : "Content-Length".equalsIgnoreCase((String) a[0]) ? contentLength : null;
            case "toByteArray" -> {
                bodyReads.incrementAndGet();
                yield bytes;
            }
            case "body" -> throw new AssertionError("body() copies the whole message");
            default -> answers.containsKey(m) ? answers.get(m) : Fakes.DEFAULT;
        });
    }

    LoginPage login(String host) {
        return store.host(host).orElseThrow().login();
    }

    @Test
    void onlyHostsTheRadarKnowsAreLookedAt() {
        watch.accept(response("vpn.example.com", "/remote/login", 200, null, MimeType.HTML, "<input type=password>"));
        assertEquals(List.of(), store.all());
        assertEquals(0, bodyReads.get());
    }

    @Test
    void notesTheStrongestSignAndStopsReadingBodies() {
        store.found("example.com", List.of("vpn.example.com"));
        watch.accept(response("vpn.example.com", "/", 200, null, MimeType.JSON, "<input type=password>"));
        assertNull(login("vpn.example.com"));
        assertEquals(0, bodyReads.get(), "only HTML bodies are read");
        watch.accept(response("VPN.example.com", "/login", 200, null, MimeType.HTML, "<form><input name=p TYPE = 'Password'>"));
        assertEquals(new LoginPage(LoginPage.Kind.PASSWORD_FORM, "Password form", "/login"), login("vpn.example.com"));
        watch.accept(response("vpn.example.com", "/other", 200, null, MimeType.HTML, "<input type=password>"));
        assertEquals("/login", login("vpn.example.com").path());
        assertEquals(1, bodyReads.get(), "a host with a login page is not read again");
        watch.accept(response("vpn.example.com", "/x", 401, "NTLM", MimeType.HTML, ""));
        assertEquals("NTLM sign-in", login("vpn.example.com").label());
        watch.accept(response("vpn.example.com", "/remote/login", 200, null, MimeType.HTML, ""));
        assertEquals("FortiGate SSL VPN", login("vpn.example.com").label());
    }

    @Test
    void readsOnlyTheStartOfABigBody() {
        store.found("example.com", List.of("a.example.com"));
        String body = "x".repeat(LoginWatch.BODY_LIMIT) + "<input type=password>";
        watch.accept(response("a.example.com", "/", 200, null, MimeType.HTML, body));
        assertNull(login("a.example.com"));
        assertEquals(1, bodyReads.get());
    }

    @Test
    void aPageWithoutTheWordSkipsTheRegex() {
        store.found("example.com", List.of("a.example.com"));
        watch.accept(response("a.example.com", "/", 200, null, MimeType.HTML, "<html>" + "x".repeat(1000) + "</html>"));
        assertNull(login("a.example.com"));
        assertEquals(1, bodyReads.get());
        assertEquals(0, regexScans.get());
    }

    @Test
    void onlyTheBodyIsSearched() {
        store.found("example.com", List.of("a.example.com"));
        watch.accept(response("a.example.com", "/", 200, null, MimeType.HTML, "HTTP/1.1 200 OK\r\nX-Note: type=password\r\n\r\n",
                "<p>hi</p>", null));
        assertNull(login("a.example.com"));
    }

    @Test
    void hugeResponsesAreNotRead() {
        store.found("example.com", List.of("a.example.com"));
        String head = "HTTP/1.1 200 OK\r\n\r\n";
        watch.accept(response("a.example.com", "/", 200, null, MimeType.HTML, head, "<input type=password>",
                String.valueOf(LoginWatch.MAX_BODY + 1)));
        assertNull(login("a.example.com"));
        assertEquals(0, bodyReads.get());
        watch.accept(response("a.example.com", "/", 200, null, MimeType.HTML, head, "<input type=password>", "junk"));
        assertEquals("Password form", login("a.example.com").label());
    }

    @Test
    void aBodyOverTheCapIsNotSearchedEvenWithoutContentLength() {
        // Chunked answers carry no Content-Length; the size Burp holds decides.
        store.found("example.com", List.of("a.example.com"));
        length = (int) LoginWatch.MAX_BODY + 100;
        watch.accept(response("a.example.com", "/", 200, null, MimeType.HTML, "<input type=password>"));
        assertNull(login("a.example.com"));
        assertEquals(0, regexScans.get());
    }

    @Test
    void aHostIsSearchedThirtyTimesWithoutAPasswordFieldAndThenLeftAlone() {
        store.found("example.com", List.of("a.example.com", "b.example.com"));
        for (int i = 0; i < 30; i++) {
            watch.accept(response("a.example.com", "/p" + i, 200, null, MimeType.HTML, "<p>no form</p>"));
        }
        assertEquals(30, bodyReads.get());
        watch.accept(response("a.example.com", "/x", 200, null, MimeType.HTML, "<input type=password>"));
        assertEquals(30, bodyReads.get());
        assertNull(login("a.example.com"));
        watch.accept(response("b.example.com", "/x", 200, null, MimeType.HTML, "<input type=password>"));
        assertEquals("Password form", login("b.example.com").label());
    }
}
