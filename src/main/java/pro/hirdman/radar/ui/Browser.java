package pro.hirdman.radar.ui;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.util.function.Consumer;

/** Opens a link in the system browser; where there is none, says so in {@code error}. */
public final class Browser {

    private Browser() {
    }

    public static void open(String url, Consumer<String> error) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
        } catch (IOException | RuntimeException e) {
            error.accept("Hirdman Radar: cannot open " + url + ": " + e);
            return;
        }
        error.accept("Hirdman Radar: no browser to open here. The link is " + url);
    }
}
