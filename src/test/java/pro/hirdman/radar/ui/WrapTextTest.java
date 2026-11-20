package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Font;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import org.junit.jupiter.api.Test;

class WrapTextTest {

    @Test
    void readsLikeALabelThatWrapsByWords() {
        WrapText t = new WrapText("A long line about what leaves Burp.");
        assertEquals("A long line about what leaves Burp.", t.getText());
        assertFalse(t.isEditable());
        assertTrue(t.getLineWrap());
        assertTrue(t.getWrapStyleWord());
        assertFalse(t.isOpaque());
        assertFalse(t.isFocusable());
        assertEquals(UIManager.getFont("Label.font"), t.getFont());
        assertEquals(UIManager.getColor("Label.foreground"), t.getForeground());
    }

    @Test
    void followsTheThemeWhenItChanges() {
        Font before = UIManager.getFont("Label.font");
        WrapText t = new WrapText("x");
        try {
            UIManager.put("Label.font", new FontUIResource(before.deriveFont(before.getSize2D() + 6f)));
            t.updateUI();
            assertEquals(before.getSize2D() + 6f, t.getFont().getSize2D());
            assertFalse(t.isOpaque());
            assertFalse(t.isEditable());
        } finally {
            UIManager.put("Label.font", before);
        }
    }

    @Test
    void htmlIsShownAsText() {
        WrapText t = new WrapText("<html><b>x</b>");
        assertEquals("<html><b>x</b>", t.getText());
    }
}
