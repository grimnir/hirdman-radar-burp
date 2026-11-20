package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.http.HttpService;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FakesTest {

    @Test
    void answersByMethodName() {
        HttpService service = Fakes.fake(HttpService.class, Map.of("host", "a.example.com"));
        assertEquals("a.example.com", service.host());
    }

    @Test
    void rejectsAKeyThatIsNotAMethodOfTheType() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Fakes.fake(HttpService.class, Map.of("hostname", "a.example.com")));
        assertTrue(e.getMessage().contains("HttpService.hostname"), e.getMessage());
    }
}
