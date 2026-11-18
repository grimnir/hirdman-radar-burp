package pro.hirdman.radar.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ReplyTest {

    @Test
    void headersIgnoreCase() {
        Reply r = new Reply(429, Map.of("Retry-After", "7"), null);
        assertEquals("7", r.header("retry-after").orElseThrow());
        assertEquals("7", r.header("RETRY-AFTER").orElseThrow());
        assertEquals("", r.body());
        assertTrue(r.header("Location").isEmpty());
    }
}
