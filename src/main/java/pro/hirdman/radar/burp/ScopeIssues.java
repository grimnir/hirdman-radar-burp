package pro.hirdman.radar.burp;

import burp.api.montoya.scope.ScopeChange;
import burp.api.montoya.scope.ScopeChangeHandler;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import pro.hirdman.radar.model.HostResult;

/** After a scope change, rows checked earlier may now be due their issues. The pass runs off Burp's thread. */
public final class ScopeIssues implements ScopeChangeHandler {

    /** "Add to scope" on many hosts makes one change per host: they are gathered this long into one pass. */
    static final Duration GATHER = Duration.ofSeconds(1);

    private final Supplier<List<HostResult>> rows;
    private final BooleanSupplier auto;
    private final ToIntFunction<List<HostResult>> reportAll;
    private final Executor executor;
    private final Consumer<String> error;
    private final BiConsumer<Runnable, Duration> later;
    private final AtomicBoolean pending = new AtomicBoolean();

    /** {@code later} runs a task after a delay, without blocking the caller. */
    public ScopeIssues(Supplier<List<HostResult>> rows, BooleanSupplier auto, ToIntFunction<List<HostResult>> reportAll,
            Executor executor, Consumer<String> error, BiConsumer<Runnable, Duration> later) {
        this.rows = rows;
        this.auto = auto;
        this.reportAll = reportAll;
        this.executor = executor;
        this.error = error;
        this.later = later;
    }

    /** Scope edits come in bursts: changes made while a pass waits are covered by that pass. */
    @Override
    public void scopeChanged(ScopeChange change) {
        if (pending.compareAndSet(false, true)) {
            later.accept(this::queuePass, GATHER);
        }
    }

    private void queuePass() {
        try {
            executor.execute(this::pass);
        } catch (RejectedExecutionException e) {
            pending.set(false);
        }
    }

    private void pass() {
        pending.set(false);
        try {
            if (auto.getAsBoolean()) {
                reportAll.applyAsInt(rows.get());
            }
        } catch (RuntimeException e) {
            error.accept("Hirdman Radar: issues after a scope change could not be created: " + e);
        }
    }
}
