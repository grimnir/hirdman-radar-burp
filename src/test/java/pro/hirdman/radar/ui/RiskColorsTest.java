package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Color;
import java.util.List;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.Risk;

class RiskColorsTest {

    static final Color LIGHT_BG = Color.WHITE;
    static final Color DARK_BG = new Color(0x2B2B2B);
    /** Table backgrounds of both themes, the striped rows included. */
    static final List<Color> LIGHT_ROWS = List.of(LIGHT_BG, new Color(0xEEEEEE), new Color(0xF2F2F2));
    static final List<Color> DARK_ROWS = List.of(DARK_BG, new Color(0x383838), new Color(0x333333));

    @Test
    void riskColorsMeetContrastOnEveryRow() {
        for (Risk r : List.of(Risk.HIGH, Risk.MEDIUM)) {
            for (Color bg : LIGHT_ROWS) {
                assertTrue(RiskColors.contrast(RiskColors.text(r, false), bg) >= 4.5, r + " on " + bg);
            }
            for (Color bg : DARK_ROWS) {
                assertTrue(RiskColors.dark(bg));
                assertTrue(RiskColors.contrast(RiskColors.text(r, true), bg) >= 4.5, r + " on " + bg);
            }
        }
    }

    @Test
    void colorsAreTheSpecOnes() {
        assertEquals(new Color(0xC62828), RiskColors.text(Risk.HIGH, false));
        assertEquals(new Color(0xFF7B7B), RiskColors.text(Risk.HIGH, true));
        assertEquals(new Color(0xA84D08), RiskColors.text(Risk.MEDIUM, false));
        assertEquals(new Color(0xF59E0B), RiskColors.text(Risk.MEDIUM, true));
        assertNull(RiskColors.text(Risk.LOW, false));
        assertNull(RiskColors.text(Risk.NONE, true));
    }

    @Test
    void contrastIsTheWcagRatio() {
        assertEquals(21.0, RiskColors.contrast(Color.BLACK, Color.WHITE), 0.01);
        assertEquals(21.0, RiskColors.contrast(Color.WHITE, Color.BLACK), 0.01);
        assertEquals(1.0, RiskColors.contrast(DARK_BG, DARK_BG), 0.001);
        assertEquals(4.54, RiskColors.contrast(new Color(0x767676), Color.WHITE), 0.01);
    }

    @Test
    void darkMeansADimBackground() {
        assertTrue(RiskColors.dark(DARK_BG));
        assertFalse(RiskColors.dark(LIGHT_BG));
        assertFalse(RiskColors.dark(new Color(0x808080)));
        assertTrue(RiskColors.dark(new Color(0x7E7E7E)));
        assertFalse(RiskColors.dark(null));
    }

    @Test
    void readableFallsBackWhenFaint() {
        Color fallback = Color.BLACK;
        assertEquals(new Color(0x767676), RiskColors.readable(new Color(0x767676), fallback, Color.WHITE));
        assertEquals(fallback, RiskColors.readable(new Color(0x999999), fallback, Color.WHITE));
        assertEquals(fallback, RiskColors.readable(null, fallback, Color.WHITE));
        assertEquals(fallback, RiskColors.readable(new Color(0x999999), fallback, null));
    }
}
