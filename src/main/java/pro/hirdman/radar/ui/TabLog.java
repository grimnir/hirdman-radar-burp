package pro.hirdman.radar.ui;

import java.util.function.BiConsumer;
import java.util.function.Consumer;

/** Burp's event log and Errors tab as the parts of the tab use them, so they need no Montoya types. */
interface TabLog {

    /** An event in Burp's event log. */
    void info(String message);

    void error(String message);

    void error(String message, Throwable cause);

    static TabLog of(Consumer<String> info, Consumer<String> error, BiConsumer<String, Throwable> errorWithCause) {
        return new TabLog() {
            @Override
            public void info(String message) {
                info.accept(message);
            }

            @Override
            public void error(String message) {
                error.accept(message);
            }

            @Override
            public void error(String message, Throwable cause) {
                errorWithCause.accept(message, cause);
            }
        };
    }
}
