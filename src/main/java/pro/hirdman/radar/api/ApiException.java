package pro.hirdman.radar.api;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/** A failed call to the radar server: no answer, an HTTP error status, or an unreadable answer. */
public final class ApiException extends Exception {

    private static final long serialVersionUID = 1L;

    /** Error bodies above this size are not searched for a message. */
    private static final int MAX_ERROR_BODY = 64 * 1024;

    public enum Kind { UNREACHABLE, HTTP, MALFORMED }

    private final Kind kind;
    private final int status;
    private final @Nullable Duration retryAfter;
    private final @Nullable String serverMessage;
    private final boolean blocked;

    private ApiException(Kind kind, int status, @Nullable Duration retryAfter, @Nullable String serverMessage,
            @Nullable String message, @Nullable Throwable cause) {
        this(kind, status, retryAfter, serverMessage, message, cause, false);
    }

    private ApiException(Kind kind, int status, @Nullable Duration retryAfter, @Nullable String serverMessage,
            @Nullable String message, @Nullable Throwable cause, boolean blocked) {
        super(message, cause);
        this.kind = kind;
        this.status = status;
        this.retryAfter = retryAfter;
        this.serverMessage = serverMessage;
        this.blocked = blocked;
    }

    public static ApiException unreachable(IOException cause) {
        return new ApiException(Kind.UNREACHABLE, 0, null, null, "No answer from the server: " + cause.getMessage(), cause);
    }

    public static ApiException http(Reply r) {
        String msg = errorText(r.body());
        return new ApiException(Kind.HTTP, r.status(), retryAfter(r), msg,
                "HTTP " + r.status() + (msg == null ? "" : ": " + msg), null);
    }

    public static ApiException malformed(@Nullable String why, @Nullable Throwable cause) {
        return new ApiException(Kind.MALFORMED, 0, null, null, Json.oneLine("Unexpected answer: " + why), cause);
    }

    /** The plugin stopped the request itself; sending it again would not help. Counts as an unusable answer. */
    public static ApiException blocked(@Nullable String reason) {
        return new ApiException(Kind.MALFORMED, 0, null, null, reason, null, true);
    }

    public boolean blocked() {
        return blocked;
    }

    public Kind kind() {
        return kind;
    }

    /** HTTP status, 0 when there was no HTTP answer. */
    public int status() {
        return status;
    }

    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }

    /** The server's {@code error} text, one line, or null. */
    public @Nullable String serverMessage() {
        return serverMessage;
    }

    private static @Nullable Duration retryAfter(Reply r) {
        return r.header("Retry-After")
                .map(String::trim)
                .filter(v -> v.matches("\\d{1,9}"))
                .map(v -> Duration.ofSeconds(Long.parseLong(v)))
                .orElse(null);
    }

    private static @Nullable String errorText(String body) {
        if (body.isEmpty() || body.length() > MAX_ERROR_BODY) {
            return null;
        }
        try {
            JsonElement e = JsonParser.parseString(body);
            JsonElement err = e.isJsonObject() ? e.getAsJsonObject().get("error") : null;
            if (err != null && err.isJsonPrimitive() && err.getAsJsonPrimitive().isString()) {
                return Json.oneLine(err.getAsString());
            }
        } catch (RuntimeException ex) {
            // Not JSON (an HTML gateway page, say): there is no server message to show.
        }
        return null;
    }
}
