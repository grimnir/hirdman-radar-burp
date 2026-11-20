package pro.hirdman.radar.ui;

import java.awt.event.KeyEvent;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.SwingUtilities;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.model.ResultStore;

/** "Check in-scope hosts": walks the site map in the background, then asks on the EDT; nothing is sent before the user agrees. */
final class ScopeCheckButton {

    static final String TEXT = "Check in-scope hosts";
    static final String READING = "Reading site map...";

    final JButton button = new JButton(TEXT);

    private final Supplier<Options> options;
    private final ResultStore store;
    private final JobQueue queue;
    private final Supplier<List<String>> scopeHosts;
    private final Function<Options, Meta.Limits> limitsNow;
    private final Executor background;
    private final TabLog log;
    private final Consumer<String> message;
    private final SendConfirm confirm;

    /**
     * {@code scopeHosts} lists the in-scope hosts of the site map and {@code limitsNow} asks the server for its limits;
     * both run in the background.
     */
    ScopeCheckButton(Supplier<Options> options, ResultStore store, JobQueue queue, Supplier<List<String>> scopeHosts,
            Function<Options, Meta.Limits> limitsNow, Executor background, TabLog log, Consumer<String> message,
            SendConfirm confirm) {
        this.options = options;
        this.store = store;
        this.queue = queue;
        this.scopeHosts = scopeHosts;
        this.limitsNow = limitsNow;
        this.background = background;
        this.log = log;
        this.message = message;
        this.confirm = confirm;
        button.setMnemonic(KeyEvent.VK_I);
        button.addActionListener(e -> checkScope());
    }

    private void checkScope() {
        Options o = options.get();
        if (o.offForProject()) {
            message.accept(ServerLine.OFF_FOR_PROJECT.text());
            return;
        }
        button.setEnabled(false);
        // A big site map takes seconds to walk.
        button.setText(READING);
        background.execute(() -> {
            ScopeCheck plan = scopePlan(o);
            Meta.Limits limits = plan == null || plan.isEmpty() ? null : limitsNow.apply(o);
            SwingUtilities.invokeLater(() -> askScope(plan, limits == null ? null : limits.hostsLeft()));
        });
    }

    /** What the in-scope hosts of the site map give; null when the site map could not be read. */
    private @Nullable ScopeCheck scopePlan(Options o) {
        try {
            return ScopeCheck.plan(scopeHosts.get(), o.serverHost(), store::lastChecked, Instant.now());
        } catch (RuntimeException e) {
            log.error("Hirdman Radar: could not read the site map", e);
            return null;
        }
    }

    private void askScope(@Nullable ScopeCheck c, @Nullable Integer hostsLeft) {
        button.setEnabled(true);
        button.setText(TEXT);
        if (c == null) {
            return;
        }
        if (c.isEmpty()) {
            message.accept(c.nothing());
        } else if (confirm.ask(c.question(hostsLeft))) {
            queue.submit(JobKind.CHECK_HOSTS, null, c.hosts(), false);
        }
    }
}
