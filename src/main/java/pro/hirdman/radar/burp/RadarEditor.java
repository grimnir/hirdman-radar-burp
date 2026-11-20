package pro.hirdman.radar.burp;

import static pro.hirdman.radar.ui.PlainText.button;
import static pro.hirdman.radar.ui.PlainText.plain;
import static pro.hirdman.radar.ui.PlainText.tip;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.HierarchyEvent;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.Timer;
import org.jspecify.annotations.Nullable;
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
    static final String CHECK_TIP = "Sends this host to the radar server now, even if it was checked in the last 24 h.";
    static final String PRIVATE = "Private project is ticked in the Hirdman Radar tab, so nothing is sent to the server.";

    private final ResultStore store;
    private final Function<String, Job> check;
    private final BooleanSupplier offForProject;
    private final JPanel panel = new JPanel(new BorderLayout(0, 8));
    /** One read-only text, so numbers and dates can be selected and copied into a report. */
    final JTextArea text = new JTextArea();
    final JButton button = button("Check this host");
    final JButton showButton = button("Show in Hirdman Radar tab");
    final JLabel queuedLabel = plain(new JLabel());
    /** Drawn as a plain line of text; opens hirdman.pro in the browser. */
    final JButton fullCheck = button(HostView.FULL_CHECK);
    private @Nullable HttpRequestResponse current;
    private @Nullable String host;
    /** The check queued from this view and the row at that moment; null when there is none. */
    private @Nullable Job job;
    private @Nullable HostResult queuedFrom;
    private final Timer ticker = new Timer(1000, e -> refresh());

    /**
     * {@code check} queues a leak check of one host; {@code show} shows a host in the plugin tab, as the context menu
     * does; {@code open} opens a link in the browser; {@code theme} applies Burp's look to the view.
     */
    public RadarEditor(ResultStore store, Function<String, Job> check, Consumer<String> show, BooleanSupplier offForProject,
            Consumer<String> open, Consumer<Component> theme) {
        this.store = store;
        this.check = check;
        this.offForProject = offForProject;
        text.setEditable(false);
        text.setLineWrap(true);
        text.setWrapStyleWord(true);
        JScrollPane scroll = new JScrollPane(text);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(button);
        actions.add(showButton);
        actions.add(queuedLabel);
        fullCheck.setBorderPainted(false);
        fullCheck.setContentAreaFilled(false);
        fullCheck.setMargin(new Insets(0, 0, 0, 0));
        fullCheck.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        fullCheck.setToolTipText("Opens hirdman.pro in the browser.");
        fullCheck.setVisible(false);
        JPanel more = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        more.add(fullCheck);
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        panel.add(actions, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        panel.add(more, BorderLayout.SOUTH);
        button.addActionListener(e -> checkAgain());
        showButton.addActionListener(e -> {
            if (host != null) {
                show.accept(host);
            }
        });
        fullCheck.addActionListener(e -> open.accept(HostView.FULL_CHECK_URL));
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
        if (job != null && (job.state() == JobState.DONE || !row.equals(Optional.ofNullable(queuedFrom)))) {
            job = null;
        }
        boolean waiting = job != null && !job.state().finished();
        boolean off = offForProject.getAsBoolean();
        String shownText = row.map(r -> String.join("\n", HostView.lines(r, Instant.now()))).orElse("");
        if (!shownText.equals(text.getText())) {
            // Set only on a change, so the ticker does not drop a selection being copied.
            text.setText(shownText);
            text.setCaretPosition(0);
        }
        fullCheck.setVisible(row.filter(HostView::suggestsFullCheck).isPresent());
        button.setEnabled(row.isPresent() && !waiting && !off);
        button.setToolTipText(off ? PRIVATE : CHECK_TIP);
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
        panel.revalidate();
        panel.repaint();
        if (waiting && panel.isShowing()) {
            ticker.start();
        } else {
            ticker.stop();
        }
    }

    private void checkAgain() {
        Optional<HostResult> row = row();
        if (host != null && row.isPresent() && !offForProject.getAsBoolean()) {
            job = check.apply(host);
            queuedFrom = row.get();
            refresh();
        }
    }

    private Optional<HostResult> row() {
        return host == null ? Optional.empty() : store.host(host);
    }

    List<String> lineTexts() {
        return text.getText().isEmpty() ? List.of() : List.of(text.getText().split("\n", -1));
    }

    @Override
    public @Nullable HttpRequest getRequest() {
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
    public @Nullable Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    /** Burp may hand in messages without a request or service; those get no tab. */
    private static Optional<String> hostOf(@Nullable HttpRequestResponse rr) {
        if (rr == null || rr.request() == null || rr.request().httpService() == null) {
            return Optional.empty();
        }
        return HostNames.normalize(rr.request().httpService().host());
    }
}
