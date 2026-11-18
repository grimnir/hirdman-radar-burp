package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.Reply;
import pro.hirdman.radar.api.Transport;

class BurpTransportTest {

    static final URI JOBS = URI.create("https://scan.hirdman.pro/api/v1/jobs");

    final List<String> calls = new ArrayList<>();
    final RequestOptions verified = fake(RequestOptions.class, Map.of());
    final RequestOptions options = fake(RequestOptions.class, Map.of("withUpstreamTLSVerification", verified));
    final AtomicReference<Object> sentOptions = new AtomicReference<>();
    boolean verify;
    boolean off;
    final AtomicReference<HttpRequest> request = new AtomicReference<>();
    final AtomicReference<Object> answer = new AtomicReference<>();
    final AtomicReference<Duration> timeout = new AtomicReference<>();

    final Http http = fake(Http.class, (m, a) -> {
        calls.add("send " + (a[0] == request.get()) + " " + (a.length > 1 && a[1] == options));
        sentOptions.set(a.length > 1 ? a[1] : null);
        Object x = answer.get();
        if (x instanceof RuntimeException e) {
            throw e;
        }
        return x;
    });

    final BurpTransport transport = new BurpTransport(http, url -> {
        calls.add("url " + url);
        request.set(fake(HttpRequest.class, (m, a) -> {
            calls.add(m + " " + String.join(" ", List.of(a).stream().map(String::valueOf).toList()));
            return request.get();
        }));
        return request.get();
    }, d -> {
        timeout.set(d);
        return options;
    }, () -> verify, () -> off);

    @Test
    void nothingIsSentWhileTheProjectIsOff() {
        off = true;
        IOException e = assertThrows(IOException.class,
                () -> transport.send("GET", java.net.URI.create("https://scan.hirdman.pro/api/v1/meta"), Map.of(), null, Duration.ofSeconds(5)));
        assertEquals("Private project: nothing is sent to the radar server", e.getMessage());
        assertEquals(List.of(), calls);
    }

    static HttpHeader header(String name, String value) {
        return fake(HttpHeader.class, Map.of("name", name, "value", value));
    }

    static HttpRequestResponse response(int status, List<HttpHeader> headers, String body) {
        HttpResponse r = fake(HttpResponse.class, Map.of("statusCode", (short) status, "headers", headers, "bodyToString", body,
                "toByteArray", fake(ByteArray.class, Map.of("length", body.length())), "bodyOffset", 0));
        Map<String, Object> rr = new LinkedHashMap<>();
        rr.put("response", r);
        return fake(HttpRequestResponse.class, rr);
    }

    @Test
    void sendsMethodHeadersAndBodyThroughBurp() throws IOException {
        answer.set(response(202, List.of(header("Content-Type", "application/json"), header("X-Seen", "1"), header("x-seen", "2")),
                "{\"job_id\":\"j1\"}"));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "HirdmanRadar/0.1.0");
        Reply r = transport.send("POST", JOBS, headers, "{\"domain\":\"example.com\"}", Duration.ofSeconds(30));
        assertEquals(List.of("url https://scan.hirdman.pro/api/v1/jobs", "withMethod POST", "withHeader Content-Type application/json",
                "withHeader User-Agent HirdmanRadar/0.1.0", "withBody {\"domain\":\"example.com\"}", "send true true"), calls);
        assertEquals(Duration.ofSeconds(30), timeout.get());
        assertEquals(new Reply(202, Map.of("content-type", "application/json", "x-seen", "1"), "{\"job_id\":\"j1\"}"), r);
    }

    @Test
    void aRepeatedHeaderKeepsItsFirstValue() throws IOException {
        answer.set(response(429, List.of(header("Retry-After", "7"), header("Retry-After", "9")), ""));
        Reply r = transport.send("GET", JOBS, Map.of(), null, Duration.ofSeconds(1));
        assertEquals("7", r.header("retry-after").orElseThrow());
    }

    @Test
    void theCertificateIsVerifiedWhileTheSettingIsOn() throws IOException {
        answer.set(response(200, List.of(), "{}"));
        verify = true;
        transport.send("GET", JOBS, Map.of(), null, Duration.ofSeconds(5));
        assertSame(verified, sentOptions.get());
        verify = false;
        transport.send("GET", JOBS, Map.of(), null, Duration.ofSeconds(5));
        assertSame(options, sentOptions.get());
    }

    @Test
    void getSendsNoBody() throws IOException {
        answer.set(response(200, List.of(), "{}"));
        transport.send("GET", URI.create("https://scan.hirdman.pro/api/v1/meta"), Map.of(), null, Duration.ofSeconds(15));
        assertEquals(List.of("url https://scan.hirdman.pro/api/v1/meta", "withMethod GET", "send true true"), calls);
    }

    @Test
    void noResponseIsNoAnswer() {
        Map<String, Object> none = new LinkedHashMap<>();
        none.put("response", null);
        answer.set(fake(HttpRequestResponse.class, none));
        IOException e = assertThrows(IOException.class, () -> transport.send("GET", JOBS, Map.of(), null, Duration.ofSeconds(1)));
        assertEquals("No response from scan.hirdman.pro", e.getMessage());
        answer.set(null);
        assertThrows(IOException.class, () -> transport.send("GET", JOBS, Map.of(), null, Duration.ofSeconds(1)));
    }

    @Test
    void aBurpErrorIsNoAnswer() {
        IllegalStateException boom = new IllegalStateException("network down");
        answer.set(boom);
        IOException e = assertThrows(IOException.class, () -> transport.send("GET", JOBS, Map.of(), null, Duration.ofSeconds(1)));
        assertEquals("No response from scan.hirdman.pro: network down", e.getMessage());
        assertSame(boom, e.getCause());
    }

    @Test
    void anAnswerOverTheCapIsRefusedBeforeItBecomesText() {
        // No bodyToString answer: reading the body as text would fail the test with another exception.
        HttpResponse r = fake(HttpResponse.class, Map.of("statusCode", (short) 200, "headers", List.of(),
                "toByteArray", fake(ByteArray.class, Map.of("length", Transport.MAX_BODY + 101)), "bodyOffset", 100));
        Map<String, Object> rr = new LinkedHashMap<>();
        rr.put("response", r);
        answer.set(fake(HttpRequestResponse.class, rr));
        assertThrows(Transport.TooLarge.class, () -> transport.send("GET", JOBS, Map.of(), null, Duration.ofSeconds(5)));
    }
}
