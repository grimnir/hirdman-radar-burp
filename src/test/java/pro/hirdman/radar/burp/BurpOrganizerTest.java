package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.sitemap.SiteMapNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.LoginPage;

class BurpOrganizerTest {

    static final LoginPage OWA = new LoginPage(LoginPage.Kind.KNOWN_PATH, "Outlook on the web", "/owa/");
    static final LoginPage FORM = new LoginPage(LoginPage.Kind.PASSWORD_FORM, "Password form", "/");

    /** What reached Organizer: the URL of the item and the note it carries. */
    record Sent(Object from, String note) {
    }

    final List<Sent> sent = new ArrayList<>();
    final List<String> siteMapUrls = new ArrayList<>();
    final List<Object> siteMapItems = new ArrayList<>();
    final List<ProxyHttpRequestResponse> history = new ArrayList<>();
    int siteMapWalks;
    int historyWalks;

    BurpOrganizer organizer() {
        return new BurpOrganizer(this::walkSiteMap, this::walkHistory, (req, resp) -> item(req, resp, ""),
                item -> sent.add(new Sent(item.request().url(), item.annotations().notes())));
    }

    List<HttpRequestResponse> walkSiteMap(SiteMapFilter filter) {
        siteMapWalks++;
        List<HttpRequestResponse> out = new ArrayList<>();
        for (int i = 0; i < siteMapUrls.size(); i++) {
            HttpRequestResponse item = (HttpRequestResponse) siteMapItems.get(i);
            if (filter.matches(fake(SiteMapNode.class, Map.of("url", siteMapUrls.get(i), "requestResponse", item)))) {
                out.add(item);
            }
        }
        return out;
    }

    List<ProxyHttpRequestResponse> walkHistory(ProxyHistoryFilter filter) {
        historyWalks++;
        return history.stream().filter(filter::matches).toList();
    }

    static HostResult row(String host, LoginPage login, int stealer, int work, int personal) {
        HostStatus status = stealer + work + personal > 0 ? HostStatus.CHECKED : HostStatus.CLEAN;
        return new HostResult(host, "example.com", status, stealer, work, personal, 0, List.of(), Instant.EPOCH, List.of(), login);
    }

    static HttpRequest request(String url) {
        String path = url.replaceFirst("^https?://[^/]*", "").replaceFirst("\\?.*", "");
        return fake(HttpRequest.class, Map.of("url", url, "pathWithoutQuery", path.isEmpty() ? "/" : path));
    }

    static HttpResponse response(int status, MimeType mime, String body) {
        String head = "HTTP/1.1 " + status + " X\r\n\r\n";
        String message = head + body;
        ByteArray bytes = fake(ByteArray.class, (m, a) -> switch (m) {
            case "length" -> message.length();
            case "indexOf" -> {
                int from = (Integer) a[a.length - 2];
                int to = Math.min((Integer) a[a.length - 1], message.length());
                if (a[0] instanceof Pattern pattern) {
                    Matcher matcher = pattern.matcher(message).region(from, to);
                    yield matcher.find() ? matcher.start() : -1;
                }
                int at = message.substring(from, to).toLowerCase(Locale.ROOT).indexOf(((String) a[0]).toLowerCase(Locale.ROOT));
                yield at < 0 ? -1 : from + at;
            }
            default -> Fakes.DEFAULT;
        });
        return fake(HttpResponse.class, (m, a) -> switch (m) {
            case "statusCode" -> (short) status;
            case "mimeType" -> mime;
            case "headerValue" -> null;
            case "bodyOffset" -> head.length();
            case "toByteArray" -> bytes;
            default -> Fakes.DEFAULT;
        });
    }

    static Annotations annotations(String notes) {
        return fake(Annotations.class, (m, a) -> switch (m) {
            case "notes" -> notes;
            case "withNotes" -> annotations((String) a[0]);
            default -> Fakes.DEFAULT;
        });
    }

    static HttpRequestResponse item(HttpRequest request, HttpResponse response, String notes) {
        return fake(HttpRequestResponse.class, (m, a) -> switch (m) {
            case "request" -> request;
            case "response" -> response;
            case "hasResponse" -> response != null;
            case "annotations" -> annotations(notes);
            case "withAnnotations" -> item(request, response, ((Annotations) a[0]).notes());
            default -> Fakes.DEFAULT;
        });
    }

    void inSiteMap(String url, HttpResponse response) {
        siteMapUrls.add(url);
        siteMapItems.add(item(request(url), response, ""));
    }

    void inHistory(String url, HttpResponse response) {
        history.add(fake(ProxyHttpRequestResponse.class, Map.of("finalRequest", request(url), "originalResponse", response,
                "hasResponse", true, "annotations", annotations(""))));
    }

    @Test
    void sendsTheSiteMapItemThatShowsTheLoginPageWithCountsOnly() {
        inSiteMap("https://mail.example.com/", response(302, MimeType.HTML, ""));
        inSiteMap("https://mail.example.com/owa/auth/x.css", response(200, MimeType.CSS, ""));
        inSiteMap("https://mail.example.com/owa/auth/logon.aspx?a=1", response(200, MimeType.HTML, "<form>"));
        inSiteMap("https://other.example.com/owa/", response(200, MimeType.HTML, ""));
        String line = organizer().send(List.of(row("mail.example.com", OWA, 12, 3, 5)));
        assertEquals(List.of(new Sent("https://mail.example.com/owa/auth/logon.aspx?a=1",
                "Hirdman Radar: 12 infostealer records, 3 work accounts, 5 personal accounts;"
                        + " prioritise auth testing")), sent);
        assertEquals("Hirdman Radar: sent 1 login page to Organizer", line);
        assertEquals(1, siteMapWalks);
        assertEquals(0, historyWalks, "the site map had it");
    }

    @Test
    void aPasswordFormIsFoundByItsBody() {
        inSiteMap("https://app.example.com/", response(200, MimeType.HTML, "<p>hello</p>"));
        inSiteMap("https://app.example.com/?next=1", response(200, MimeType.HTML, "<input type=\"password\">"));
        organizer().send(List.of(row("app.example.com", FORM, 1, 0, 0)));
        assertEquals(List.of(new Sent("https://app.example.com/?next=1",
                "Hirdman Radar: 1 infostealer record; prioritise auth testing")), sent);
    }

    @Test
    void fallsBackToTheNewestProxyHistoryItem() {
        inHistory("https://mail.example.com/owa/", response(200, MimeType.HTML, ""));
        inHistory("https://other.example.com/owa/", response(200, MimeType.HTML, ""));
        inHistory("https://MAIL.example.com/owa/auth/logon.aspx", response(200, MimeType.HTML, ""));
        inHistory("https://mail.example.com/owa/x.js", response(404, MimeType.HTML, ""));
        String line = organizer().send(List.of(row("mail.example.com", OWA, 0, 0, 2)));
        assertEquals(List.of(new Sent("https://MAIL.example.com/owa/auth/logon.aspx",
                "Hirdman Radar: 2 personal accounts; prioritise auth testing")), sent);
        assertEquals("Hirdman Radar: sent 1 login page to Organizer", line);
    }

    @Test
    void saysWhichLoginPagesBurpHasNoItemFor() {
        inSiteMap("https://a.example.com/owa/", response(200, MimeType.HTML, ""));
        String line = organizer().send(List.of(row("a.example.com", OWA, 0, 0, 0), row("b.example.com", OWA, 1, 0, 0),
                row("c.example.com", FORM, 1, 0, 0), row("d.example.com", null, 9, 0, 0)));
        assertEquals(List.of(new Sent("https://a.example.com/owa/", "Hirdman Radar: no leaks known for this host")), sent);
        assertEquals("Hirdman Radar: sent 1 login page to Organizer. Burp has no stored response for b.example.com/owa/,"
                + " c.example.com/", line);
        assertEquals(1, historyWalks, "one history walk for all the hosts the site map lacks");
    }

    @Test
    void rowsWithoutALoginPageSendNothing() {
        String line = organizer().send(List.of(row("d.example.com", null, 9, 0, 0)));
        assertEquals(List.of(), sent);
        assertEquals("Hirdman Radar: none of the selected hosts has a login page", line);
        assertEquals(0, siteMapWalks);
    }

    @Test
    void longListsOfMissingPagesAreCut() {
        List<HostResult> rows = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            rows.add(row("h" + i + ".example.com", OWA, 1, 0, 0));
        }
        String line = organizer().send(rows);
        assertTrue(line.endsWith("h4.example.com/owa/ and 3 more"), line);
    }

    @Test
    void aNoteTheUserLeftIsKept() {
        siteMapUrls.add("https://a.example.com/owa/");
        siteMapItems.add(item(request("https://a.example.com/owa/"), response(200, MimeType.HTML, ""), "check MFA"));
        organizer().send(List.of(row("a.example.com", OWA, 1, 0, 0)));
        assertEquals("check MFA | Hirdman Radar: 1 infostealer record; prioritise auth testing", sent.get(0).note());
    }

    @Test
    void anUncheckedHostSaysSo() {
        HostResult r = new HostResult("a.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null, List.of(), OWA);
        assertEquals("Hirdman Radar: not checked for leaks yet", BurpOrganizer.note(r));
    }
}
