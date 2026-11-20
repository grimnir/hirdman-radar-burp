package pro.hirdman.radar.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.LoginPage;
import pro.hirdman.radar.model.ResultStore;

/**
 * Notes login pages of hosts the plugin has a row for, from responses Burp already has. Runs on Burp's threads, so a body is
 * read only for a host without any login page yet, only for HTML and only its start. Nothing is sent anywhere.
 */
public final class LoginWatch implements Consumer<HttpResponseReceived> {

    static final int BODY_LIMIT = 512 * 1024;
    /** No login page is this big; a bigger response is not touched at all. */
    static final long MAX_BODY = 8L * 1024 * 1024;
    /** Bodies searched on one host without finding a password field, after which its pages are no longer read. */
    static final int SCANS_PER_HOST = 30;
    /** Linear on any body: no window after "<input" that a hostile page could repeat. Matches script setting type too. */
    private static final Pattern PASSWORD_FIELD = Pattern.compile("(?i)type\\s*=\\s*[\"']?password");

    private final ResultStore store;
    private final Map<String, AtomicInteger> scans = new ConcurrentHashMap<>();

    public LoginWatch(ResultStore store) {
        this.store = store;
    }

    @Override
    public void accept(HttpResponseReceived response) {
        HttpRequest request = response.initiatingRequest();
        if (request == null || request.httpService() == null) {
            return;
        }
        String host = request.httpService().host();
        Optional<HostResult> row = store.peek(host);
        if (row.isEmpty()) {
            return;
        }
        LoginPage known = row.get().login();
        if (known != null && known.kind() == LoginPage.Kind.KNOWN_PATH) {
            return;
        }
        int status = response.statusCode();
        LoginPage.detect(request.pathWithoutQuery(), status, status == 401 ? response.headerValue("WWW-Authenticate") : null,
                        () -> known == null && budgetLeft(row.get().host()) && response.mimeType() == MimeType.HTML
                                && withinBudget(row.get().host()) && passwordField(response))
                .ifPresent(p -> store.noteLogin(host, p));
    }

    /** Whether the host still has body reads left; does not use one up. */
    private boolean budgetLeft(String host) {
        AtomicInteger scanned = scans.get(host);
        return scanned == null || scanned.get() < SCANS_PER_HOST;
    }

    /** Counts one more body read on the host, up to the budget, and says whether this one is still within it. */
    private boolean withinBudget(String host) {
        AtomicInteger scanned = scans.computeIfAbsent(host, h -> new AtomicInteger());
        return scanned.getAndUpdate(n -> Math.min(n + 1, SCANS_PER_HOST)) < SCANS_PER_HOST;
    }

    /** Searches the body in place: body() would copy the whole message first. The cheap word search spares the regex. */
    private static boolean passwordField(HttpResponseReceived response) {
        if (tooBig(response.headerValue("Content-Length"))) {
            return false;
        }
        ByteArray message = response.toByteArray();
        int from = response.bodyOffset();
        if (message.length() - from > MAX_BODY) {
            return false;
        }
        int to = (int) Math.min(message.length(), (long) from + BODY_LIMIT);
        return from < to && message.indexOf("password", false, from, to) >= 0 && message.indexOf(PASSWORD_FIELD, from, to) >= 0;
    }

    private static boolean tooBig(String contentLength) {
        try {
            return contentLength != null && Long.parseLong(contentLength.strip()) > MAX_BODY;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
