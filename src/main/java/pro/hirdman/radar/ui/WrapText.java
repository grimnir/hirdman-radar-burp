package pro.hirdman.radar.ui;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Read-only text that wraps at word boundaries and otherwise looks like a label: for lines too long for one row.
 * A text area never reads its text as HTML. Put it where the layout sets its width (BorderLayout, BoxLayout).
 */
public final class WrapText extends JTextArea {

    public WrapText(String text) {
        super(text);
        setEditable(false);
        setLineWrap(true);
        setWrapStyleWord(true);
        setFocusable(false);
    }

    @Override
    public void updateUI() {
        super.updateUI();
        // The text area theme would bring its own font, colours and border.
        setOpaque(false);
        setBorder(null);
        setFont(UIManager.getFont("Label.font"));
        setForeground(UIManager.getColor("Label.foreground"));
    }

    @Override
    public void setBounds(int x, int y, int width, int height) {
        boolean resized = width != getWidth();
        super.setBounds(x, y, width, height);
        // The wrapped height is known only once the width is, so the layout runs again with it.
        if (resized && getPreferredSize().height != height) {
            SwingUtilities.invokeLater(this::revalidate);
        }
    }
}
