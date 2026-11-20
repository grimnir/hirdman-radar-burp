package pro.hirdman.radar.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import pro.hirdman.radar.jobs.StatusText;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.LoginPage;

/**
 * Copies login pages Burp already holds (site map first, then proxy history) to Organizer with a counts-only note.
 * Nothing is sent to any host. Walks Burp's stores, so call it off the EDT.
 */
public final class BurpOrganizer {

    /** Missing pages named in the event log line; the rest are counted. */
    static final int LISTED = 5;

    private final Function<SiteMapFilter, List<HttpRequestResponse>> siteMap;
    private final Function<ProxyHistoryFilter, List<ProxyHttpRequestResponse>> history;
    private final BiFunction<HttpRequest, HttpResponse, HttpRequestResponse> pair;
    private final Consumer<HttpRequestResponse> organizer;

    public BurpOrganizer(MontoyaApi api) {
        this(api.siteMap()::requestResponses, api.proxy()::history, HttpRequestResponse::httpRequestResponse,
                api.organizer()::sendToOrganizer);
    }

    /** Burp's factories work only inside Burp, so tests pass their own. */
    BurpOrganizer(Function<SiteMapFilter, List<HttpRequestResponse>> siteMap,
            Function<ProxyHistoryFilter, List<ProxyHttpRequestResponse>> history,
            BiFunction<HttpRequest, HttpResponse, HttpRequestResponse> pair, Consumer<HttpRequestResponse> organizer) {
        this.siteMap = siteMap;
        this.history = history;
        this.pair = pair;
        this.organizer = organizer;
    }

    /** Sends the login page of each row that has one and returns the event log line. */
    public String send(List<HostResult> rows) {
        Map<String, HostResult> byHost = new LinkedHashMap<>();
        rows.stream().filter(r -> r.login() != null).forEach(r -> byHost.put(key(r), r));
        if (byHost.isEmpty()) {
            return "Hirdman Radar: none of the selected hosts has a login page";
        }
        Map<String, HttpRequestResponse> found = fromSiteMap(byHost);
        if (found.size() < byHost.size()) {
            Map<String, HostResult> rest = new HashMap<>(byHost);
            rest.keySet().removeAll(found.keySet());
            found.putAll(fromHistory(rest));
        }
        List<String> missing = new ArrayList<>();
        int sent = 0;
        for (Map.Entry<String, HostResult> e : byHost.entrySet()) {
            HttpRequestResponse item = found.get(e.getKey());
            if (item == null) {
                missing.add(e.getValue().host() + e.getValue().login().path());
                continue;
            }
            // A note the user left on the item stays in front of the radar's.
            Annotations annotations = item.annotations();
            String userNote = annotations.notes() == null ? "" : annotations.notes().strip();
            String note = note(e.getValue());
            organizer.accept(item.withAnnotations(annotations.withNotes(userNote.isEmpty() ? note : userNote + " | " + note)));
            sent++;
        }
        String line = "Hirdman Radar: sent " + StatusText.count(sent, "login page") + " to Organizer";
        if (missing.isEmpty()) {
            return line;
        }
        String listed = String.join(", ", missing.subList(0, Math.min(LISTED, missing.size())));
        return line + ". Burp has no stored response for " + listed
                + (missing.size() > LISTED ? " and " + (missing.size() - LISTED) + " more" : "");
    }

    /** One site map walk: the filter keeps items under each login path, which are then checked for the login page itself. */
    private Map<String, HttpRequestResponse> fromSiteMap(Map<String, HostResult> byHost) {
        List<HttpRequestResponse> items = siteMap.apply(node -> hostOf(node.url(), byHost) != null);
        Map<String, HttpRequestResponse> found = new HashMap<>();
        for (HttpRequestResponse item : items) {
            HostResult row = item.hasResponse() ? hostOf(item.request().url(), byHost) : null;
            if (row != null && shows(item.request(), item.response(), row.login())) {
                String host = key(row);
                // An HTML page beats a script or an image under the same path.
                HttpRequestResponse had = found.get(host);
                if (had == null || !html(had.response()) && html(item.response())) {
                    found.put(host, item);
                }
            }
        }
        return found;
    }

    /** One proxy history walk; the newest item that shows the login page wins. */
    private Map<String, HttpRequestResponse> fromHistory(Map<String, HostResult> byHost) {
        Map<String, ProxyHttpRequestResponse> newest = new HashMap<>();
        history.apply(p -> {
            HostResult row = p.hasResponse() ? hostOf(p.finalRequest().url(), byHost) : null;
            if (row != null && shows(p.finalRequest(), p.originalResponse(), row.login())) {
                newest.put(key(row), p);
            }
            return false;
        });
        Map<String, HttpRequestResponse> found = new HashMap<>();
        newest.forEach((host, p) -> found.put(host, pair.apply(p.finalRequest(), p.originalResponse())
                .withAnnotations(p.annotations())));
        return found;
    }

    private static String key(HostResult row) {
        return row.host().toLowerCase(Locale.ROOT);
    }

    /** The selected row whose host the URL is on, under its login path, or null. Only the URL string is read. */
    private static HostResult hostOf(String url, Map<String, HostResult> byHost) {
        if (url == null) {
            return null;
        }
        int end = BurpSiteMap.authorityEnd(url);
        if (end < 0) {
            return null;
        }
        HostResult row = byHost.get(BurpSiteMap.host(url.substring(0, end).toLowerCase(Locale.ROOT)));
        return row != null && startsWith(url.substring(end), row.login()) ? row : null;
    }

    /** "/owa/" also takes "/owa"; "/" takes every path. Case is ignored, as when the page was noted. */
    private static boolean startsWith(String path, LoginPage login) {
        String prefix = login.path();
        if (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        return path != null && path.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    /** The response shows the same login page the plugin noted from traffic. */
    private static boolean shows(HttpRequest request, HttpResponse response, LoginPage login) {
        if (request == null || response == null) {
            return false;
        }
        int status = response.statusCode();
        return LoginPage.detect(request.pathWithoutQuery(), status, status == 401 ? response.headerValue("WWW-Authenticate") : null,
                () -> html(response) && LoginWatch.passwordField(response)).filter(login::equals).isPresent();
    }

    private static boolean html(HttpResponse response) {
        return response != null && response.mimeType() == MimeType.HTML;
    }

    /** Counts only, in the words of the Proxy history note: what the radar knows about the host. */
    static String note(HostResult r) {
        if (!r.checked()) {
            return "Hirdman Radar: not checked for leaks yet";
        }
        List<String> counts = ProxyHighlight.counts(r);
        return counts.isEmpty() ? "Hirdman Radar: no leaks known for this host"
                : "Hirdman Radar: " + String.join(", ", counts) + "; prioritise auth testing";
    }
}
