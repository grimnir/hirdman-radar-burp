package pro.hirdman.radar.ui;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import javax.swing.SwingUtilities;

/** Swing components are built on the event thread. */
public final class Edt {

    private Edt() {
    }

    /** Runs {@code work} on the event thread and returns its result; called on that thread, it just runs. */
    public static <T> T call(Supplier<T> work) {
        if (SwingUtilities.isEventDispatchThread()) {
            return work.get();
        }
        AtomicReference<T> out = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> out.set(work.get()));
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException r) {
                throw r;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new IllegalStateException(cause);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while building on the event thread", e);
        }
        return out.get();
    }
}
