package pro.hirdman.radar.burp;

import burp.api.montoya.persistence.PersistedObject;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.ResultsJson;

/** Results in the Burp project file (counts only), saved at most every 5 s and once more on unload. */
public final class ProjectStore {

    static final String KEY = "hirdman.radar.results";
    static final String UNREADABLE_KEY = KEY + ".unreadable";
    static final Duration EVERY = Duration.ofSeconds(30);

    private final PersistedObject data;
    private final Consumer<String> errors;
    private final AtomicBoolean dirty = new AtomicBoolean();
    private ResultStore store;
    private ScheduledExecutorService timer;

    public ProjectStore(PersistedObject data, Consumer<String> errors) {
        this.data = data;
        this.errors = errors;
    }

    /** Reads the saved results and watches them for changes from then on. Data it could not read is kept aside first. */
    public ResultStore load() {
        String saved = data.getString(KEY);
        AtomicBoolean unclean = new AtomicBoolean();
        store = ResultsJson.read(saved, e -> {
            unclean.set(true);
            errors.accept(e);
        });
        if (unclean.get()) {
            data.setString(UNREADABLE_KEY, saved);
            errors.accept("Hirdman Radar: the saved results are kept unchanged in this project as " + UNREADABLE_KEY);
        }
        store.addListener(() -> dirty.set(true));
        return store;
    }

    public synchronized void start() {
        if (timer == null) {
            timer = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "hirdman-radar-save");
                t.setDaemon(true);
                return t;
            });
            timer.scheduleWithFixedDelay(this::tick, EVERY.toMillis(), EVERY.toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    synchronized boolean running() {
        return timer != null && !timer.isShutdown();
    }

    /** Extension unload: stops the timer and saves what is left. */
    public void close() {
        synchronized (this) {
            if (timer != null) {
                timer.shutdownNow();
            }
        }
        tick();
    }

    /** Saves when something changed since the last save; a failed save is logged and tried on the next tick. */
    synchronized void tick() {
        if (store == null || !dirty.getAndSet(false)) {
            return;
        }
        try {
            data.setString(KEY, ResultsJson.write(store));
        } catch (RuntimeException e) {
            dirty.set(true);
            errors.accept("Hirdman Radar: results could not be saved: " + e);
        }
    }
}
