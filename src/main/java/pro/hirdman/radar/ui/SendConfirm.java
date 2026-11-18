package pro.hirdman.radar.ui;

import java.awt.Component;
import javax.swing.JOptionPane;

/** Asks before more host names leave Burp than one keyless server check takes. */
@FunctionalInterface
public interface SendConfirm {

    int QUIET_HOSTS = 50;

    /** True when the user agreed. */
    boolean ask(String question);

    /** True when the hosts may be sent: few of them, or the user agreed. */
    default boolean allows(int hosts) {
        return hosts <= QUIET_HOSTS || ask(question(hosts));
    }

    static String question(int hosts) {
        return "Send " + hosts + " host names to the Hirdman Radar server for a leak check?";
    }

    /** A Send / Cancel dialog over the window that holds {@code parent}. */
    static SendConfirm dialog(Component parent) {
        String[] buttons = {"Send", "Cancel"};
        return q -> JOptionPane.showOptionDialog(parent, q, "Hirdman Radar", JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE, null, buttons, buttons[0]) == 0;
    }
}
