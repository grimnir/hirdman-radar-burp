package pro.hirdman.radar.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/** Local HTTP server that answers from a script and records every request. */
final class FakeServer implements AutoCloseable {

    record Recorded(String method, String path, String query, Map<String, String> headers, String body) {
    }

    private record Answer(int status, String body, Map<String, String> headers) {
    }

    private final HttpServer server;
    private final Deque<Answer> script = new ArrayDeque<>();
    private final List<Recorded> requests = new CopyOnWriteArrayList<>();
    private volatile boolean dropAll;

    private FakeServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    static FakeServer start() throws IOException {
        return new FakeServer();
    }

    /** Queues one answer; headers come as name, value pairs. */
    synchronized FakeServer reply(int status, String body, String... headers) {
        Map<String, String> h = new LinkedHashMap<>();
        for (int i = 0; i + 1 < headers.length; i += 2) {
            h.put(headers[i], headers[i + 1]);
        }
        script.add(new Answer(status, body, h));
        return this;
    }

    /** Every request from now on gets its connection closed without an answer. */
    FakeServer dropConnections() {
        dropAll = true;
        return this;
    }

    URI uri() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    List<Recorded> requests() {
        return List.copyOf(requests);
    }

    private void handle(HttpExchange ex) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        ex.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(Locale.ROOT), v.get(0)));
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.add(new Recorded(ex.getRequestMethod(), ex.getRequestURI().getPath(), ex.getRequestURI().getRawQuery(),
                headers, body));
        if (dropAll) {
            // An exception from the handler makes HttpServer close the connection with no answer.
            throw new IOException("scripted drop");
        }
        Answer a;
        synchronized (this) {
            a = script.isEmpty() ? new Answer(500, "no scripted answer", Map.of()) : script.poll();
        }
        a.headers().forEach((k, v) -> ex.getResponseHeaders().add(k, v));
        byte[] bytes = a.body().getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(a.status(), bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
