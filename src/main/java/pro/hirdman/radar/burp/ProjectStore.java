package pro.hirdman.radar.burp;

import burp.api.montoya.persistence.PersistedObject;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.ResultsJson;

/**
 * Results in the Burp project file (counts only), one key per domain. Changed domains are saved every 30 s, at once by
 * {@link #saveNow}, and once more on unload.
 */
public final class ProjectStore {

    /** The single key older versions kept every row in; read once and moved to the per-domain keys. */
    static final String KEY = "hirdman.radar.results";
    static final String UNREADABLE_KEY = KEY + ".unreadable";
    static final String DOMAIN_PREFIX = "hirdman.radar.domain.";
    static final String UNREADABLE_PREFIX = "hirdman.radar.unreadable.";
    static final Duration EVERY = Duration.ofSeconds(30);
    /** Unreadable data past this size is not copied aside: a hostile project would double in size. */
    static final int MAX_UNREADABLE_COPY = 1024 * 1024;

    private final PersistedObject data;
    private final Consumer<String> errors;
    private final BiConsumer<String, Throwable> failures;
    private final Set<String> dirty = ConcurrentHashMap.newKeySet();
    private @Nullable ResultStore store;
    private boolean dropLegacy;
    private @Nullable ScheduledExecutorService timer;

    /** {@code errors} takes notes about saved data, {@code failures} unexpected exceptions with their stack. */
    public ProjectStore(PersistedObject data, Consumer<String> errors, BiConsumer<String, Throwable> failures) {
        this.data = data;
        this.errors = errors;
        this.failures = failures;
    }

    /** Reads the saved results and watches them for changes from then on. Data it could not read is kept aside first. */
    public ResultStore load() {
        ResultStore store = new ResultStore();
        this.store = store;
        // Loaded rows do not fire listeners, so this hears only later changes.
        store.addDomainListener(dirty::addAll);
        for (String key : data.stringKeys()) {
            if (key.startsWith(DOMAIN_PREFIX)) {
                String domain = key.substring(DOMAIN_PREFIX.length());
                read(store, data.getString(key), UNREADABLE_PREFIX + domain,
                        "of " + domain + " are too large to keep a copy, they are replaced on the next save of that domain");
            }
        }
        // Read last: an older plugin may have written it after this one saved per domain.
        String legacy = data.getString(KEY);
        if (legacy != null) {
            dropLegacy = read(store, legacy, UNREADABLE_KEY, "are too large to keep a copy, they stay as " + KEY);
            dirty.addAll(store.domains());
            tick();
        }
        return store;
    }

    /** Reads one saved block into the store; false when unreadable data was too large to keep aside, as {@code tooLarge} says. */
    private boolean read(ResultStore store, String saved, String asideKey, String tooLarge) {
        AtomicBoolean unclean = new AtomicBoolean();
        ResultsJson.readInto(store, saved, e -> {
            unclean.set(true);
            errors.accept(e);
        });
        if (!unclean.get()) {
            return true;
        }
        if (saved.length() > MAX_UNREADABLE_COPY) {
            errors.accept("Hirdman Radar: the unreadable saved results " + tooLarge);
            return false;
        }
        data.setString(asideKey, saved);
        errors.accept("Hirdman Radar: the saved results are kept unchanged in this project as " + asideKey);
        return true;
    }

    // tick logs a failed save itself; the future is never read.
    @SuppressWarnings("FutureReturnValueIgnored")
    public synchronized void start() {
        if (timer == null) {
            ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "hirdman-radar-save");
                t.setDaemon(true);
                return t;
            });
            this.timer = timer;
            timer.scheduleWithFixedDelay(this::tick, EVERY.toMillis(), EVERY.toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    synchronized boolean running() {
        return timer != null && !timer.isShutdown();
    }

    /** Saves what changed without waiting for the timer, as when a job finishes; on the timer's thread once it runs. */
    public void saveNow() {
        synchronized (this) {
            if (timer != null) {
                try {
                    timer.execute(this::tick);
                } catch (RejectedExecutionException e) {
                    // Closed: unload has saved already.
                }
                return;
            }
        }
        tick();
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

    /** Writes each changed domain; a failed save is logged and tried on the next tick. */
    synchronized void tick() {
        if (store == null) {
            return;
        }
        RuntimeException failure = null;
        for (String domain : List.copyOf(dirty)) {
            dirty.remove(domain);
            try {
                List<HostResult> rows = store.domain(domain);
                if (rows.isEmpty()) {
                    data.deleteString(DOMAIN_PREFIX + domain);
                } else {
                    data.setString(DOMAIN_PREFIX + domain, ResultsJson.write(rows));
                }
            } catch (RuntimeException e) {
                dirty.add(domain);
                if (failure == null) {
                    failure = e;
                }
            }
        }
        if (failure != null) {
            failures.accept("Hirdman Radar: results could not be saved", failure);
        } else if (dropLegacy) {
            data.deleteString(KEY);
            dropLegacy = false;
        }
    }
}
