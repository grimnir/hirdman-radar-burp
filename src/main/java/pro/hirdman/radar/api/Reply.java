package pro.hirdman.radar.api;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/** An HTTP answer; header names are case-insensitive. */
public record Reply(int status, Map<String, String> headers, String body) {

    public Reply {
        Map<String, String> lower = new HashMap<>();
        if (headers != null) {
            headers.forEach((k, v) -> {
                if (k != null && v != null) {
                    lower.putIfAbsent(k.toLowerCase(Locale.ROOT), v);
                }
            });
        }
        headers = Map.copyOf(lower);
        body = body == null ? "" : body;
    }

    public Optional<String> header(String name) {
        return Optional.ofNullable(headers.get(name.toLowerCase(Locale.ROOT)));
    }
}
