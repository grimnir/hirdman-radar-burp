package pro.hirdman.radar.ui;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Keeps what the tab's parts log: events in {@link #infos}, error lines in {@link #errors}, the causes given in {@link #causes}. */
final class TestLog implements TabLog {

    final List<String> infos = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    final List<Throwable> causes = new CopyOnWriteArrayList<>();

    @Override
    public void info(String message) {
        infos.add(message);
    }

    @Override
    public void error(String message) {
        errors.add(message);
    }

    @Override
    public void error(String message, Throwable cause) {
        errors.add(message);
        causes.add(cause);
    }
}
