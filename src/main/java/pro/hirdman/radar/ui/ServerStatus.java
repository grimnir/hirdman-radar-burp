package pro.hirdman.radar.ui;

import static pro.hirdman.radar.ui.PlainText.label;
import static pro.hirdman.radar.ui.PlainText.plain;

import java.awt.Font;
import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.Version;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.ConnectionSettings;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.jobs.MetaGate;

/** The server line with its Try again button and release link, the TLS warning, and the footer note. */
final class ServerStatus {

    /** A Server URL is asked about once it has stayed the same this long, not on every key typed. */
    static final Duration SETTLE = Duration.ofSeconds(1);

    final JLabel label = plain(new JLabel());
    final JButton tryAgainButton = new JButton("Try again");
    final Link releaseLink = new Link("");
    final JLabel tlsWarning = label("TLS verification is off");
    final JLabel footerLabel = label(ServerLine.footer(null));

    private final Supplier<Options> options;
    private final BooleanSupplier verifyTls;
    private final MetaGate gate;
    private final Supplier<Radar> radar;
    private final Executor background;
    private final TabLog log;
    private final LongSupplier nanoTime;
    private @Nullable String watchedUrl;
    private boolean watchedOff;
    private boolean checked;
    private @Nullable String typedUrl;
    private long typedAt;
    private int serverCheck;
    private @Nullable String releaseUrl;

    /**
     * A /meta answer that reaches {@code gate}, from this check or from a job, updates the line on the EDT; {@code browse}
     * opens the release page and runs in the background.
     */
    ServerStatus(Supplier<Options> options, BooleanSupplier verifyTls, MetaGate gate, Supplier<Radar> radar, Executor background,
            TabLog log, Consumer<String> browse, LongSupplier nanoTime) {
        this.options = options;
        this.verifyTls = verifyTls;
        this.gate = gate;
        this.radar = radar;
        this.background = background;
        this.log = log;
        this.nanoTime = nanoTime;
        tryAgainButton.addActionListener(e -> check());
        tryAgainButton.setVisible(false);
        releaseLink.setVisible(false);
        releaseLink.addActionListener(e -> {
            String url = releaseUrl;
            background.execute(() -> browse.accept(url));
        });
        tlsWarning.setFont(tlsWarning.getFont().deriveFont(Font.BOLD));
        tlsWarning.setToolTipText("The radar server's certificate is not checked. Turn the check back on in Settings > "
                + "Extensions > Hirdman Radar unless a proxy re-signs HTTPS.");
        tlsWarning.setVisible(false);
        gate.addServerListener((server, m) -> SwingUtilities.invokeLater(() -> showMeta(server, m)));
    }

    /** Asks the server again when the project switch has changed, or the Server URL has changed and settled. */
    void watch() {
        tlsWarning.setVisible(!verifyTls.getAsBoolean());
        Options o = options.get();
        if (!checked || o.offForProject() != watchedOff) {
            check();
            return;
        }
        if (Objects.equals(o.serverUrl(), watchedUrl)) {
            typedUrl = null;
            return;
        }
        long now = nanoTime.getAsLong();
        if (!Objects.equals(o.serverUrl(), typedUrl)) {
            typedUrl = o.serverUrl();
            typedAt = now;
        } else if (now - typedAt >= SETTLE.toNanos()) {
            check();
        }
    }

    /** /meta in the background; a later check makes the answer of an earlier one stale. */
    void check() {
        Options o = options.get();
        checked = true;
        typedUrl = null;
        watchedUrl = o.serverUrl();
        watchedOff = o.offForProject();
        tlsWarning.setVisible(!verifyTls.getAsBoolean());
        int check = ++serverCheck;
        if (watchedOff) {
            show(ServerLine.OFF_FOR_PROJECT);
            return;
        }
        Optional<String> problem = o.serverUrlProblem();
        if (problem.isPresent()) {
            show(ServerLine.badUrl(problem.get()));
            return;
        }
        ConnectionSettings server = ConnectionSettings.of(o.serverUrl());
        background.execute(() -> {
            ServerLine failed = ask(server);
            if (failed != null) {
                SwingUtilities.invokeLater(() -> {
                    if (check == serverCheck) {
                        show(failed);
                    }
                });
            }
        });
    }

    /** Null when the server answered: the answer reaches the line through the gate. */
    private @Nullable ServerLine ask(ConnectionSettings server) {
        try {
            gate.passed(server.server(), radar.get().meta());
            return null;
        } catch (ApiException e) {
            log.error("Hirdman Radar: server check failed: " + e.getMessage());
            return ServerLine.failed(e, server.host());
        } catch (RuntimeException e) {
            log.error("Hirdman Radar: server check failed", e);
            return ServerLine.UNEXPECTED;
        }
    }

    /** The limits asked afresh, since the line's /meta answer may be old; null when unknown. Blocks: call off the EDT. */
    Meta.@Nullable Limits limitsNow(Options o) {
        if (o.serverUrlProblem().isPresent()) {
            return null;
        }
        try {
            return radar.get().meta().limits();
        } catch (ApiException | RuntimeException e) {
            // The job reports server problems itself.
            return null;
        }
    }

    /** An answer about another server than the current Server URL, or in a private project, leaves the line. */
    private void showMeta(URI server, Meta m) {
        Options o = options.get();
        if (o.offForProject() || o.serverUrlProblem().isPresent() || !ConnectionSettings.of(o.serverUrl()).server().equals(server)) {
            return;
        }
        show(ServerLine.passed(m, Version.current(), o.serverHost()));
        footerLabel.setText(ServerLine.footer(m));
    }

    private void show(ServerLine line) {
        label.setText(line.text());
        PlainText.tip(label, line.text());
        tryAgainButton.setVisible(line.tryAgain());
        releaseUrl = line.linkUrl();
        releaseLink.setText(line.linkText() == null ? "" : line.linkText());
        releaseLink.setToolTipText(line.linkUrl());
        releaseLink.setVisible(line.linkUrl() != null);
    }
}
