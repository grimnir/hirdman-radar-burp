package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.Meta.Limits;

class LimitsTextTest {

    @Test
    void freeLimitsLine() {
        assertEquals(Optional.of("Free limits: up to 50 hosts per check and 300 per hour from your address."),
                LimitsText.of(new Limits(50, 1.5, 300)));
        assertEquals(Optional.empty(), LimitsText.of(new Limits(400, 1.5, 0)));
        assertEquals(Optional.empty(), LimitsText.of(null));
    }
}
