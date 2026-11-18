package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import javax.swing.JComponent;
import javax.swing.SwingConstants;
import org.junit.jupiter.api.Test;

class PlainTextTest {

    static final String HTML = "<html><b>x</b><img src='http://127.0.0.1:9/x'>";

    @Test
    void textIsSetOnlyAfterHtmlIsTurnedOff() {
        List<JComponent> made = List.of(PlainText.label(HTML), PlainText.label(HTML, SwingConstants.CENTER),
                PlainText.button(HTML), PlainText.menu(HTML), PlainText.menuItem(HTML));
        for (JComponent c : made) {
            assertEquals(Boolean.TRUE, c.getClientProperty("html.disable"), c.getClass().getSimpleName());
            assertNull(c.getClientProperty("html"), c.getClass().getSimpleName() + " built an HTML view");
        }
        assertEquals(SwingConstants.CENTER, PlainText.label("x", SwingConstants.CENTER).getHorizontalAlignment());
        assertEquals(HTML, PlainText.menuItem(HTML).getText());
    }
}
