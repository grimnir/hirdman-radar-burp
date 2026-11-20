package pro.hirdman.radar.ui;

import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.Insets;
import java.io.IOException;
import java.net.URI;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.UIManager;

/** A focusable text link in the theme's secondary colour, or its main one when the secondary reads poorly. */
final class Link extends JButton {

    private static final String UTM = "utm_source=burp&utm_medium=plugin&utm_content=footer";

    Link(String text) {
        PlainText.plain(this);
        setText(text);
        setBorderPainted(false);
        setContentAreaFilled(false);
        setMargin(new Insets(0, 0, 0, 0));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    @Override
    public void updateUI() {
        super.updateUI();
        secondary(this);
    }

    /** One size smaller, in the theme's secondary colour or its main one when the secondary reads poorly. */
    static void secondary(JComponent c) {
        c.setForeground(RiskColors.readable(UIManager.getColor("Label.disabledForeground"), UIManager.getColor("Label.foreground"),
                UIManager.getColor("Panel.background")));
        Font f = UIManager.getFont("Label.font");
        if (f != null) {
            c.setFont(f.deriveFont(f.getSize2D() - 1f));
        }
    }

    /** A hirdman.pro link from the plugin's interface gets source tags; other sites are left as they are. */
    static String tagged(String url) {
        URI u;
        try {
            u = URI.create(url);
        } catch (IllegalArgumentException e) {
            return url;
        }
        String host = u.getHost();
        if (host == null || !(host.equals("hirdman.pro") || host.endsWith(".hirdman.pro")) || u.getRawFragment() != null) {
            return url;
        }
        if (u.getRawQuery() != null) {
            return url + "&" + UTM;
        }
        return url + (u.getRawPath().isEmpty() ? "/" : "") + "?" + UTM;
    }

    /** Opens the page in the system browser; blocks, so call it off the EDT. */
    static void browse(String url, TabLog log) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
        } catch (IOException | RuntimeException e) {
            log.error("Hirdman Radar: cannot open " + url + ": " + e);
            return;
        }
        log.error("Hirdman Radar: no browser to open here. The page is " + url);
    }
}
