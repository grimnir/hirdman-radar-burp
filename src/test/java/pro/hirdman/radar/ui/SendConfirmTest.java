package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import org.junit.jupiter.api.Test;

class SendConfirmTest {

    static List<JButton> buttons(Container c) {
        List<JButton> out = new ArrayList<>();
        for (Component child : c.getComponents()) {
            if (child instanceof JButton b) {
                out.add(b);
            } else if (child instanceof Container sub) {
                out.addAll(buttons(sub));
            }
        }
        return out;
    }

    @Test
    void cancelIsTheDefaultAndSendIsFirstWithAMnemonic() {
        JOptionPane pane = SendConfirm.pane("Send 60 host names?");
        assertEquals("Send 60 host names?", pane.getMessage());
        assertArrayEquals(new Object[] {"Send", "Cancel"}, pane.getOptions());
        assertEquals("Cancel", pane.getInitialValue());
        List<JButton> b = buttons(pane);
        assertEquals(List.of("Send", "Cancel"), b.stream().map(JButton::getText).toList());
        assertEquals(KeyEvent.VK_S, b.get(0).getMnemonic());
    }

    @Test
    void fewHostsGoWithoutAQuestion() {
        List<String> asked = new ArrayList<>();
        SendConfirm c = q -> {
            asked.add(q);
            return false;
        };
        assertTrue(c.allows(50));
        assertFalse(c.allows(51));
        assertEquals(List.of("Send 51 host names to the Hirdman Radar server for a leak check?"), asked);
    }
}
