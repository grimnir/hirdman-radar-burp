package pro.hirdman.radar.ui;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.plaf.basic.BasicHTML;

/**
 * Components that show server reasons, typed domains or host names: never let Swing read them as HTML. A text constructor
 * parses the text at once, so the factories turn HTML off first and only then set the text.
 */
public final class PlainText {

    private PlainText() {
    }

    public static <T extends JComponent> T plain(T c) {
        c.putClientProperty("html.disable", Boolean.TRUE);
        return c;
    }

    /** Swing's tooltip reads "<html>" text as HTML whatever the component says, so such text gets a leading space. */
    public static void tip(JComponent c, String text) {
        c.setToolTipText(text != null && BasicHTML.isHTMLString(text) ? " " + text : text);
    }

    public static JLabel label(String text) {
        JLabel l = plain(new JLabel());
        l.setText(text);
        return l;
    }

    public static JLabel label(String text, int horizontalAlignment) {
        JLabel l = label(text);
        l.setHorizontalAlignment(horizontalAlignment);
        return l;
    }

    public static JButton button(String text) {
        return withText(new JButton(), text);
    }

    public static JMenu menu(String text) {
        return withText(new JMenu(), text);
    }

    public static JMenuItem menuItem(String text) {
        return withText(new JMenuItem(), text);
    }

    private static <T extends AbstractButton> T withText(T b, String text) {
        plain(b).setText(text);
        return b;
    }
}
