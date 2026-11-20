package pro.hirdman.radar.ui;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Keeps what the tab's parts log: events in {@link #infos}, errors (without their causes) in {@link #errors}. */
final class TestLog implements TabLog {

    final List<String> infos = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();

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
    }
}
