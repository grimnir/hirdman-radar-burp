package pro.hirdman.radar.burp;

import static pro.hirdman.radar.ui.PlainText.label;
import static pro.hirdman.radar.ui.PlainText.plain;
import static pro.hirdman.radar.ui.PlainText.tip;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.HierarchyEvent;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.Timer;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobState;
import pro.hirdman.radar.model.HostNames;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.ui.HostView;

/**
 * Read-only "Hirdman Radar" tab in Burp's message editors, shown only for hosts the plugin has a row for. Holds no store
 * listener, so an editor Burp drops is simply collected; the view is redrawn when shown or given a new message, and
 * once a second while a check queued from it is on screen.
 */
public final class RadarEditor implements ExtensionProvidedHttpRequestEditor {

    static final String QUEUED = "Queued. The result shows here and in the Hirdman Radar tab.";

    private final ResultStore store;
    private final Function<String, Job> check;
    private final JPanel panel = new JPanel(new BorderLayout(0, 8));
    private final JPanel lines = new JPanel();
    final JButton button = new JButton("Check again");
    final JLabel queuedLabel = plain(new JLabel());
    private HttpRequestResponse current;
    private String host;
    /** The check queued from this view and the row at that moment; null when there is none. */
    private Job job;
    private HostResult queuedFrom;
    private final Timer ticker = new Timer(1000, e -> refresh());

    /** {@code check} queues a leak check of one host; {@code theme} applies Burp's look to the view. */
    public RadarEditor(ResultStore store, Function<String, Job> check, Consumer<Component> theme) {
        this.store = store;
        this.check = check;
        lines.setLayout(new BoxLayout(lines, BoxLayout.Y_AXIS));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(button);
        actions.add(queuedLabel);
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        panel.add(lines, BorderLayout.NORTH);
        panel.add(actions, BorderLayout.CENTER);
        button.addActionListener(e -> checkAgain());
        panel.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && panel.isShowing()) {
                refresh();
            }
        });
        theme.accept(panel);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse rr) {
        return hostOf(rr).flatMap(store::host).isPresent();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse rr) {
        current = rr;
        host = hostOf(rr).orElse(null);
        job = null;
        refresh();
    }

    /** Redraws from the store; the queued note stays until the row changes, a failed check keeps its reason. */
    void refresh() {
        Optional<HostResult> row = row();
        if (job != null && (job.state() == JobState.DONE || !row.equals(Optional.of(queuedFrom)))) {
            job = null;
        }
        boolean waiting = job != null && !job.state().finished();
        lines.removeAll();
        row.ifPresent(r -> HostView.lines(r).forEach(t -> lines.add(label(t))));
        button.setText(row.map(HostView::button).orElse("Check again"));
        button.setEnabled(row.isPresent() && !waiting);
        // A job waiting for the hourly limit says when it goes on; the tip holds what the narrow label cuts.
        String note;
        if (job == null) {
            note = "";
        } else if (waiting && job.state() != JobState.RETRYING) {
            note = QUEUED;
        } else {
            note = job.status();
        }
        queuedLabel.setText(note);
        tip(queuedLabel, note.isEmpty() ? null : note);
        lines.revalidate();
        lines.repaint();
        if (waiting && panel.isShowing()) {
            ticker.start();
        } else {
            ticker.stop();
        }
    }

    private void checkAgain() {
        Optional<HostResult> row = row();
        if (row.isPresent()) {
            job = check.apply(host);
            queuedFrom = row.get();
            refresh();
        }
    }

    private Optional<HostResult> row() {
        return host == null ? Optional.empty() : store.host(host);
    }

    List<String> lineTexts() {
        return Arrays.stream(lines.getComponents()).map(c -> ((JLabel) c).getText()).toList();
    }

    @Override
    public HttpRequest getRequest() {
        return current == null ? null : current.request();
    }

    @Override
    public String caption() {
        return "Hirdman Radar";
    }

    @Override
    public Component uiComponent() {
        return panel;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    /** Burp may hand in messages without a request or service; those get no tab. */
    private static Optional<String> hostOf(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null || rr.request().httpService() == null) {
            return Optional.empty();
        }
        return HostNames.normalize(rr.request().httpService().host());
    }
}
