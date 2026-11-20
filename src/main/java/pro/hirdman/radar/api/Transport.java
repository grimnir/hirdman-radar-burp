package pro.hirdman.radar.api;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/** Sends one HTTP request; in Burp this goes through Burp's own HTTP stack. */
public interface Transport {

    /** The largest answer read; a larger one is refused before it is turned into text. */
    int MAX_BODY = 8 * 1024 * 1024;

    /** The answer was larger than {@link #MAX_BODY}. */
    final class TooLarge extends IOException {
        static final String MESSAGE = "answer larger than 4 MB";

        public TooLarge() {
            super(MESSAGE);
        }
    }

    /** Burp changed the request on its way out (session rules, other extensions); its answer is not used. */
    final class Altered extends IOException {
        public Altered(String message) {
            super(message);
        }
    }

    /** Throws IOException when no answer came back: refused, DNS, timeout, TLS. Never follows redirects. */
    Reply send(String method, URI url, Map<String, String> headers, @Nullable String body, Duration timeout)
            throws IOException;
}
