package pro.hirdman.radar.api;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Test transport over java.net.http, configured like Burp's: no redirects. */
final class JdkTransport implements Transport {

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    public Reply send(String method, URI url, Map<String, String> headers, String body, Duration timeout)
            throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(url)
                .timeout(timeout)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(b::header);
        try {
            HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
            Map<String, String> h = new LinkedHashMap<>();
            r.headers().map().forEach((k, v) -> h.put(k.toLowerCase(Locale.ROOT), v.get(0)));
            return new Reply(r.statusCode(), h, r.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
        }
    }
}
