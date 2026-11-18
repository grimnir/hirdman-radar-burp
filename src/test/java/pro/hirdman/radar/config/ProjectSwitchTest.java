package pro.hirdman.radar.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.persistence.PersistedObject;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.burp.Fakes;

class ProjectSwitchTest {

    final Map<String, Boolean> saved = new HashMap<>();
    final PersistedObject data = fake(PersistedObject.class, (m, a) -> switch (m) {
        case "getBoolean" -> saved.get((String) a[0]);
        case "setBoolean" -> {
            saved.put((String) a[0], (Boolean) a[1]);
            yield null;
        }
        default -> Fakes.DEFAULT;
    });

    @Test
    void onUntilTheProjectTurnsItOffAndTheProjectFileRemembers() {
        ProjectSwitch s = new ProjectSwitch(data);
        assertFalse(s.off());
        s.set(true);
        assertTrue(s.off());
        assertEquals(Map.of("hirdman.radar.off", true), saved);
        assertTrue(new ProjectSwitch(data).off());
        s.set(false);
        assertFalse(new ProjectSwitch(data).off());
    }
}
