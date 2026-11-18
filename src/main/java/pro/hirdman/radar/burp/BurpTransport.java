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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
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

    /** {@code off}: the project keeps everything in Burp, so nothing is sent, not even a job already running. */
    public BurpTransport(Http http, BooleanSupplier verifyTls, BooleanSupplier off) {
        this(http, HttpRequest::httpRequestFromUrl, BurpTransport::options, verifyTls, off);
    }

    /** Burp's factories work only inside Burp, so tests pass their own. */
    BurpTransport(Http http, Function<String, HttpRequest> fromUrl, Function<Duration, RequestOptions> options,
            BooleanSupplier verifyTls, BooleanSupplier off) {
        this.http = http;
        this.fromUrl = fromUrl;
        this.options = options;
        this.verifyTls = verifyTls;
        this.off = off;
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

    private static RequestOptions options(Duration timeout) {
        return RequestOptions.requestOptions().withResponseTimeout(timeout.toMillis()).withRedirectionMode(RedirectionMode.NEVER);
    }
}
