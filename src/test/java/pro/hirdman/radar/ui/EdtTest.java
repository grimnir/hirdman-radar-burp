package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;

class EdtTest {

    @Test
    void runsOnTheEventThreadFromAnyThread() throws Exception {
        assertTrue(Edt.call(SwingUtilities::isEventDispatchThread));
        AtomicBoolean inner = new AtomicBoolean();
        SwingUtilities.invokeAndWait(() -> inner.set(Edt.call(SwingUtilities::isEventDispatchThread)));
        assertTrue(inner.get());
    }

    @Test
    void anExceptionWhileBuildingReachesTheCaller() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> Edt.call(() -> {
            throw new IllegalStateException("broken tab");
        }));
        assertEquals("broken tab", e.getMessage());
    }
}
