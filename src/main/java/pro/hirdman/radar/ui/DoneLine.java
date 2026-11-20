package pro.hirdman.radar.ui;

import static pro.hirdman.radar.ui.PlainText.plain;

import java.awt.BorderLayout;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobState;
import pro.hirdman.radar.jobs.StatusText;
import pro.hirdman.radar.model.HostResult;

/** The result of the last finished domain check, kept above the Jobs strip until closed: a scan can take minutes. */
final class DoneLine {

    final JPanel panel = new JPanel(new BorderLayout(8, 0));
    final JLabel label = plain(new JLabel());
    final JButton closeButton = PlainText.button("Close");
    private final Set<Long> seen = new HashSet<>();

    DoneLine() {
        panel.add(label, BorderLayout.CENTER);
        panel.add(closeButton, BorderLayout.EAST);
        panel.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 0));
        panel.setVisible(false);
        closeButton.addActionListener(e -> panel.setVisible(false));
    }

    /** Shows a domain check that has finished since the last call; {@code rows} gives a domain's rows. */
    void show(List<Job> jobs, Function<String, List<HostResult>> rows) {
        for (Job j : jobs) {
            if (j.kind() == JobKind.FIND_AND_CHECK && j.state() == JobState.DONE && seen.add(j.id())) {
                List<HostResult> r = rows.apply(j.domain());
                label.setText(text(j.domain(), r.stream().filter(HostResult::hasLeaks).count(), r.size()));
                panel.setVisible(true);
            }
        }
    }

    static String text(@Nullable String domain, long withLeaks, long hosts) {
        return "Done: " + domain + ", " + withLeaks + " of " + StatusText.count(hosts, "host") + " with leaks.";
    }
}
