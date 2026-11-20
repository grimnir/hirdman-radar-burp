package pro.hirdman.radar.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.KeyEvent;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import org.jspecify.annotations.Nullable;

/** Asks before more host names leave Burp than one keyless server check takes. */
@FunctionalInterface
public interface SendConfirm {

    int QUIET_HOSTS = 50;
    String SEND = "Send";
    String CANCEL = "Cancel";

    /** True when the user agreed. */
    boolean ask(String question);

    /** True when the hosts may be sent: few of them, or the user agreed. */
    default boolean allows(int hosts) {
        return hosts <= QUIET_HOSTS || ask(question(hosts));
    }

    static String question(int hosts) {
        return "Send " + hosts + " host names to the Hirdman Radar server for a leak check?";
    }

    /** A Send / Cancel dialog over the window {@code parent} gives, Burp's main window in Burp. */
    static SendConfirm dialog(Supplier<Component> parent) {
        return q -> {
            JOptionPane pane = pane(q);
            JDialog d = pane.createDialog(parent.get(), "Hirdman Radar");
            d.setVisible(true);
            d.dispose();
            return SEND.equals(pane.getValue());
        };
    }

    /** Cancel is the default, so a stray Enter sends nothing; Send stays first, on Alt+S. */
    static JOptionPane pane(String question) {
        String[] buttons = {SEND, CANCEL};
        JOptionPane pane = new JOptionPane(question, JOptionPane.QUESTION_MESSAGE, JOptionPane.DEFAULT_OPTION, null, buttons,
                CANCEL);
        JButton send = button(pane, SEND);
        if (send != null) {
            send.setMnemonic(KeyEvent.VK_S);
        }
        return pane;
    }

    private static @Nullable JButton button(Container c, String text) {
        for (Component child : c.getComponents()) {
            if (child instanceof JButton b && text.equals(b.getText())) {
                return b;
            }
            if (child instanceof Container sub) {
                JButton found = button(sub, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
