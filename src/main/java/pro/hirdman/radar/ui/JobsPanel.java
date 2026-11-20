package pro.hirdman.radar.ui;

import static pro.hirdman.radar.ui.PlainText.plain;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobState;

/** The Jobs strip: one row per job with its kind, subject, status and the buttons its state allows. */
public final class JobsPanel extends JPanel {

    static final String REMOVE_FINISHED = "Remove finished";
    private static final int TIP_HOSTS = 20;

    private final JobQueue queue;
    private final List<Row> rows = new ArrayList<>();
    private final JButton removeFinished = PlainText.button(REMOVE_FINISHED);
    private boolean removeFinishedShown;

    public JobsPanel(JobQueue queue) {
        super(new GridBagLayout());
        this.queue = queue;
        removeFinished.addActionListener(e -> queue.removeFinished());
    }

    public boolean hasJobs() {
        return !rows.isEmpty();
    }

    /** Updates rows in place while the job list is the same, so focus stays on a button; rebuilds when it changes. */
    public void show(List<Job> jobs) {
        // One finished job already has its own Remove button.
        boolean manyFinished = jobs.stream().filter(j -> j.state().finished()).count() > 1;
        boolean same = manyFinished == removeFinishedShown && jobs.size() == rows.size();
        for (int i = 0; same && i < jobs.size(); i++) {
            same = rows.get(i).job == jobs.get(i);
        }
        if (!same) {
            removeAll();
            rows.clear();
            for (int i = 0; i < jobs.size(); i++) {
                Row row = new Row(jobs.get(i));
                row.addTo(this, i);
                rows.add(row);
            }
            if (manyFinished) {
                add(removeFinished, cell(3, jobs.size(), 0));
            }
            removeFinishedShown = manyFinished;
        }
        rows.forEach(Row::update);
        revalidate();
        repaint();
    }

    private final class Row {

        final Job job;
        final JLabel kind = plain(new JLabel());
        final JLabel label = plain(new JLabel());
        final JLabel status = plain(new JLabel());
        final JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        @Nullable JobState shownState;

        Row(Job job) {
            this.job = job;
            PlainText.tip(label, hostsTip(job));
            buttons.setOpaque(false);
            // A long server reason shrinks instead of pushing the buttons out of view.
            status.setMinimumSize(new Dimension(0, status.getMinimumSize().height));
        }

        void addTo(JPanel p, int y) {
            p.add(kind, cell(0, y, 0));
            p.add(label, cell(1, y, 0));
            p.add(status, cell(2, y, 1));
            p.add(buttons, cell(3, y, 0));
        }

        void update() {
            kind.setText(job.kind().label());
            label.setText(job.label());
            status.setText(job.status());
            PlainText.tip(status, job.status());
            JobState state = job.state();
            if (state == shownState) {
                return;
            }
            shownState = state;
            buttons.removeAll();
            switch (state) {
                case WAITING, RUNNING -> button("Cancel", queue::cancel);
                case RETRYING -> {
                    button("Retry now", queue::retryNow);
                    button("Stop", queue::cancel);
                }
                case FAILED -> {
                    button("Retry", queue::retry);
                    button("Remove", queue::remove);
                }
                case DONE, CANCELLED -> button("Remove", queue::remove);
            }
        }

        private void button(String text, Consumer<Job> action) {
            JButton b = PlainText.button(text);
            b.addActionListener(e -> action.accept(job));
            buttons.add(b);
        }
    }

    /** The first 20 hosts of a host check; null for a domain job, whose label is the domain. */
    private static @Nullable String hostsTip(Job job) {
        if (job.kind() != JobKind.CHECK_HOSTS) {
            return null;
        }
        List<String> hosts = job.hosts();
        String shown = String.join(", ", hosts.subList(0, Math.min(TIP_HOSTS, hosts.size())));
        return hosts.size() > TIP_HOSTS ? shown + " and " + (hosts.size() - TIP_HOSTS) + " more" : shown;
    }

    private static GridBagConstraints cell(int x, int y, double weight) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x;
        c.gridy = y;
        c.weightx = weight;
        c.anchor = GridBagConstraints.WEST;
        c.fill = weight > 0 ? GridBagConstraints.HORIZONTAL : GridBagConstraints.NONE;
        c.insets = new Insets(1, 6, 1, 6);
        return c;
    }
}
