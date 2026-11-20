package pro.hirdman.radar.ui;

import java.awt.Color;
import pro.hirdman.radar.model.Risk;

/** Risk text colours for both Burp themes, striped rows included, and the WCAG contrast check behind them. */
public final class RiskColors {

    static final double MIN_CONTRAST = 4.5;

    private static final Color HIGH_LIGHT = new Color(0xC62828);
    private static final Color HIGH_DARK = new Color(0xFF7B7B);
    private static final Color MEDIUM_LIGHT = new Color(0xA84D08);
    private static final Color MEDIUM_DARK = new Color(0xF59E0B);

    private RiskColors() {
    }

    /** Null for Low and none: those use the theme's text colour. */
    public static Color text(Risk r, boolean dark) {
        return switch (r) {
            case HIGH -> dark ? HIGH_DARK : HIGH_LIGHT;
            case MEDIUM -> dark ? MEDIUM_DARK : MEDIUM_LIGHT;
            default -> null;
        };
    }

    /** A background darker than half brightness means the dark theme. */
    public static boolean dark(Color background) {
        if (background == null) {
            return false;
        }
        return Color.RGBtoHSB(background.getRed(), background.getGreen(), background.getBlue(), null)[2] < 0.5f;
    }

    /** WCAG 2 contrast ratio, 1 to 21. */
    public static double contrast(Color a, Color b) {
        double la = luminance(a);
        double lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    /** {@code preferred} when it reads well on {@code background}, else {@code fallback}. */
    public static Color readable(Color preferred, Color fallback, Color background) {
        if (preferred == null || background == null || contrast(preferred, background) < MIN_CONTRAST) {
            return fallback;
        }
        return preferred;
    }

    private static double luminance(Color c) {
        return 0.2126 * channel(c.getRed()) + 0.7152 * channel(c.getGreen()) + 0.0722 * channel(c.getBlue());
    }

    private static double channel(int v) {
        double s = v / 255.0;
        return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    }
}
