package pro.hirdman.radar.burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import pro.hirdman.radar.api.Reply;
import pro.hirdman.radar.api.Transport;

/**
 * Sends the plugin's requests through Burp's HTTP stack, so Burp's upstream proxy and network settings apply.
 * Burp does not check upstream certificates unless asked, so the server's certificate is checked while the setting is on.
 */
public final class BurpTransport implements Transport {

    private final Http http;
    private final Function<String, HttpRequest> fromUrl;
    private final Function<Duration, RequestOptions> options;
    private final BooleanSupplier verifyTls;
    private final BooleanSupplier off;
    private final Consumer<String> warn;
    private final AtomicBoolean warned = new AtomicBoolean();

    /** Headers Burp itself sets on every request; the rest must be the plugin's own. */
    private static final Set<String> BURP_HEADERS = Set.of("host", "content-length", "connection");

    /**
     * {@code off}: the project keeps everything in Burp, so nothing is sent, not even a job already running.
     * {@code warn} gets one note when Burp adds headers to the plugin's requests.
     */
    public BurpTransport(Http http, BooleanSupplier verifyTls, BooleanSupplier off, Consumer<String> warn) {
        this(http, HttpRequest::httpRequestFromUrl, BurpTransport::options, verifyTls, off, warn);
    }

    /** Burp's factories work only inside Burp, so tests pass their own. */
    BurpTransport(Http http, Function<String, HttpRequest> fromUrl, Function<Duration, RequestOptions> options,
            BooleanSupplier verifyTls, BooleanSupplier off, Consumer<String> warn) {
        this.http = http;
        this.fromUrl = fromUrl;
        this.options = options;
        this.verifyTls = verifyTls;
        this.off = off;
        this.warn = warn;
    }

    @Override
    public Reply send(String method, URI url, Map<String, String> headers, String body, Duration timeout) throws IOException {
        if (off.getAsBoolean()) {
            throw new IOException("Private project: nothing is sent to the radar server");
        }
        HttpRequest request = fromUrl.apply(url.toString()).withMethod(method);
        for (Map.Entry<String, String> h : headers.entrySet()) {
            request = request.withHeader(h.getKey(), h.getValue());
        }
        if (body != null) {
            // Burp sets Content-Length from the body.
            request = request.withBody(body);
        }
        RequestOptions o = options.apply(timeout);
        if (verifyTls.getAsBoolean()) {
            o = o.withUpstreamTLSVerification();
        }
        HttpRequestResponse sent;
        try {
            sent = http.sendRequest(request, o);
        } catch (RuntimeException e) {
            throw new IOException("No response from " + url.getHost() + ": " + e.getMessage(), e);
        }
        HttpResponse response = sent == null ? null : sent.response();
        if (response == null) {
            throw new IOException("No response from " + url.getHost());
        }
        checkSentHeaders(sent.request(), headers);
        Map<String, String> replyHeaders = new LinkedHashMap<>();
        for (HttpHeader h : response.headers()) {
            replyHeaders.putIfAbsent(h.name(), h.value());
        }
        // Measured in place: body() would copy the whole answer first.
        if (response.toByteArray().length() - response.bodyOffset() > MAX_BODY) {
            throw new TooLarge();
        }
        return new Reply(response.statusCode(), replyHeaders, response.bodyToString());
    }

    /**
     * Burp's session handling rules and other extensions can add the target's cookies or tokens to any request it
     * sends. Such a request is reported and its answer dropped, so the job stops instead of sending them again.
     */
    private void checkSentHeaders(HttpRequest sent, Map<String, String> own) throws Altered {
        if (sent == null) {
            return;
        }
        Set<String> expected = new HashSet<>(BURP_HEADERS);
        own.keySet().forEach(k -> expected.add(k.toLowerCase(Locale.ROOT)));
        List<String> added = new ArrayList<>();
        for (HttpHeader h : sent.headers()) {
            String name = h.name();
            // HTTP/2 pseudo-headers carry the method, path and host.
            if (!name.startsWith(":") && !expected.contains(name.toLowerCase(Locale.ROOT)) && !added.contains(name)) {
                added.add(name);
            }
        }
        if (added.isEmpty()) {
            return;
        }
        String message = "Burp added headers to the radar request (" + String.join(", ", added)
                + "). Exclude the radar server from session handling rules.";
        if (warned.compareAndSet(false, true)) {
            warn.accept("Hirdman Radar: " + message);
        }
        throw new Altered(message);
    }

    private static RequestOptions options(Duration timeout) {
        return RequestOptions.requestOptions().withResponseTimeout(timeout.toMillis()).withRedirectionMode(RedirectionMode.NEVER);
    }
}
