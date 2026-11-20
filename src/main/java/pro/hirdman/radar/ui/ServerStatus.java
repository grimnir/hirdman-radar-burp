package pro.hirdman.radar.ui;

import static pro.hirdman.radar.ui.PlainText.label;
import static pro.hirdman.radar.ui.PlainText.plain;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import pro.hirdman.radar.Version;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.ConnectionSettings;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.jobs.MetaGate;

/** The server line with its Try again button, and the footer note: what /meta says about the Server URL. */
final class ServerStatus {

    final JLabel label = plain(new JLabel());
    final JButton tryAgainButton = new JButton("Try again");
    final JLabel footerLabel = label(ServerLine.footer(null));

    private final Supplier<Options> options;
    private final MetaGate gate;
    private final Supplier<Radar> radar;
    private final Executor background;
    private final TabLog log;
    private String watchedUrl;
    private boolean watchedOff;
    private int serverCheck;

    /** A /meta answer that reaches {@code gate}, from this check or from a job, updates the line on the EDT. */
    ServerStatus(Supplier<Options> options, MetaGate gate, Supplier<Radar> radar, Executor background, TabLog log) {
        this.options = options;
        this.gate = gate;
        this.radar = radar;
        this.background = background;
        this.log = log;
        tryAgainButton.addActionListener(e -> check());
        tryAgainButton.setVisible(false);
        gate.addListener(m -> SwingUtilities.invokeLater(() -> showMeta(m)));
    }

    /** Asks the server again when the Server URL or the project switch has changed. */
    void watch() {
        Options o = options.get();
        if (!Objects.equals(o.serverUrl(), watchedUrl) || o.offForProject() != watchedOff) {
            check();
        }
    }

    /** /meta in the background; a later check makes the answer of an earlier one stale. */
    void check() {
        Options o = options.get();
        watchedUrl = o.serverUrl();
        watchedOff = o.offForProject();
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
    private ServerLine ask(ConnectionSettings server) {
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
    Meta.Limits limitsNow(Options o) {
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

    private void showMeta(Meta m) {
        show(ServerLine.passed(m, Version.current()));
        footerLabel.setText(ServerLine.footer(m));
    }

    private void show(ServerLine line) {
        label.setText(line.text());
        PlainText.tip(label, line.text());
        tryAgainButton.setVisible(line.tryAgain());
    }
}
