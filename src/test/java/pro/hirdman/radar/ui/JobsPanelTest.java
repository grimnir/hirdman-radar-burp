package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import javax.swing.AbstractButton;
import javax.swing.JLabel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobRunner;
import pro.hirdman.radar.jobs.JobState;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.Sleeper;
import pro.hirdman.radar.jobs.TestJobs;
import pro.hirdman.radar.model.ResultStore;

class JobsPanelTest {

    // An invalid server makes every queued job fail at once, so nothing reaches the network.
    final JobRunner runner = new JobRunner(() -> null, new ResultStore(), new MetaGate(), Sleeper.real(),
            () -> new JobRunner.RunOptions(null, "test", false, 5, true), e -> { }, e -> { });
    final JobQueue queue = new JobQueue(runner, () -> null, j -> { });
    final JobsPanel panel = new JobsPanel(queue);

    @AfterEach
    void tearDown() {
        queue.shutdown();
    }

    static Job job(JobState state, String status) {
        return TestJobs.job(JobKind.FIND_AND_CHECK, "example.com", List.of(), state, status);
    }

    static <T extends Component> List<T> all(Container c, Class<T> type) {
        List<T> out = new ArrayList<>();
        for (Component child : c.getComponents()) {
            if (type.isInstance(child)) {
                out.add(type.cast(child));
            }
            if (child instanceof Container sub) {
                out.addAll(all(sub, type));
            }
        }
        return out;
    }

    List<String> labels() {
        return all(panel, JLabel.class).stream().map(JLabel::getText).toList();
    }

    List<String> buttons() {
        return all(panel, AbstractButton.class).stream().map(AbstractButton::getText).toList();
    }

    AbstractButton button(String text) {
        return all(panel, AbstractButton.class).stream().filter(b -> b.getText().equals(text)).findFirst()
                .orElseThrow(() -> new AssertionError("no button " + text + " in " + buttons()));
    }

    static Job waitFor(Job j, JobState state) throws InterruptedException {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (j.state() != state && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertEquals(state, j.state());
        return j;
    }

    @Test
    void serverTextIsNotHtml() {
        panel.show(List.of(job(JobState.FAILED, "<html><img src='http://evil.example/x'>Failed</html>")));
        List<JLabel> labels = all(panel, JLabel.class);
        assertFalse(labels.isEmpty());
        for (JLabel l : labels) {
            assertEquals(Boolean.TRUE, l.getClientProperty("html.disable"), l.getText());
            assertNull(l.getClientProperty("html"), l.getText());
        }
    }

    @Test
    void rowShowsKindLabelAndStatus() {
        panel.show(List.of(job(JobState.RUNNING, "Checking 37 of 120, about 55 s left"),
                TestJobs.job(JobKind.CHECK_HOSTS, null, List.of("a.example.com", "b.example.com"), JobState.DONE, "Done: 2 hosts")));
        assertEquals(List.of("Check for leaks", "example.com", "Checking 37 of 120, about 55 s left",
                "Check hosts", "2 hosts", "Done: 2 hosts"), labels());
    }

    @Test
    void buttonsFollowTheState() {
        panel.show(List.of(job(JobState.WAITING, "w")));
        assertEquals(List.of("Cancel"), buttons());
        panel.show(List.of(job(JobState.RUNNING, "r")));
        assertEquals(List.of("Cancel"), buttons());
        panel.show(List.of(job(JobState.RETRYING, "x")));
        assertEquals(List.of("Retry now", "Stop"), buttons());
        panel.show(List.of(job(JobState.FAILED, "f")));
        assertEquals(List.of("Retry", "Remove"), buttons());
        panel.show(List.of(job(JobState.DONE, "d")));
        assertEquals(List.of("Remove"), buttons());
        panel.show(List.of(job(JobState.CANCELLED, "c")));
        assertEquals(List.of("Remove"), buttons());
    }

    @Test
    void cancelAndStopCancelTheJob() {
        Job waiting = job(JobState.WAITING, "w");
        panel.show(List.of(waiting));
        button("Cancel").doClick(0);
        assertEquals(JobState.CANCELLED, waiting.state());
        Job retrying = job(JobState.RETRYING, "x");
        panel.show(List.of(retrying));
        button("Stop").doClick(0);
        assertEquals(JobState.CANCELLED, retrying.state());
    }

    @Test
    void retryPutsAFailedJobBackToWaiting() {
        Job failed = job(JobState.FAILED, "f");
        panel.show(List.of(failed));
        button("Retry").doClick(0);
        assertEquals(JobState.WAITING, failed.state());
    }

    @Test
    void removeTakesTheJobOffTheQueue() throws InterruptedException {
        waitFor(queue.submit(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false), JobState.FAILED);
        panel.show(queue.jobs());
        button("Remove").doClick(0);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void retryNowEndsTheWait() throws InterruptedException {
        Job retrying = job(JobState.RETRYING, "x");
        panel.show(List.of(retrying));
        button("Retry now").doClick(0);
        assertEquals(JobState.RETRYING, retrying.state());
        long start = System.nanoTime();
        TestJobs.pause(retrying, java.time.Duration.ofSeconds(5));
        assertTrue(System.nanoTime() - start < 2_000_000_000L);
    }

    @Test
    void sameJobsKeepTheirRowsAndStatusUpdatesInPlace() {
        Job j = job(JobState.RUNNING, "Checking 1 of 3");
        panel.show(List.of(j));
        JLabel status = all(panel, JLabel.class).get(2);
        AbstractButton cancel = button("Cancel");
        TestJobs.update(j, JobState.RUNNING, "Checking 2 of 3");
        panel.show(List.of(j));
        assertSame(status, all(panel, JLabel.class).get(2));
        assertSame(cancel, button("Cancel"));
        assertEquals("Checking 2 of 3", status.getText());
    }

    @Test
    void goneJobsLoseTheirRows() {
        Job a = job(JobState.DONE, "a");
        Job b = job(JobState.DONE, "b");
        panel.show(List.of(a, b));
        assertEquals(List.of("Remove", "Remove", JobsPanel.REMOVE_FINISHED), buttons());
        panel.show(List.of(b));
        assertEquals(List.of("Check for leaks", "example.com", "b"), labels());
        panel.show(List.of());
        assertTrue(labels().isEmpty());
        assertFalse(panel.hasJobs());
    }

    @Test
    void recheckJobsSayWhatTheyAre() {
        panel.show(List.of(TestJobs.recheck(List.of("a.example.com"))));
        assertEquals(List.of("Check hosts", "Re-check failed", "Waiting in plugin queue"), labels());
        assertTrue(panel.hasJobs());
    }

    @Test
    void statusAndHostListAreInTips() {
        List<String> hosts = java.util.stream.IntStream.range(0, 25).mapToObj(i -> "h" + i + ".example.com").toList();
        Job j = TestJobs.job(JobKind.CHECK_HOSTS, null, hosts, JobState.RUNNING, "Checking 3 of 25, about 10 s left");
        Job d = job(JobState.RUNNING, "Finding subdomains");
        panel.show(List.of(j, d));
        List<JLabel> l = all(panel, JLabel.class);
        assertEquals("Checking 3 of 25, about 10 s left", l.get(2).getToolTipText());
        assertEquals(String.join(", ", hosts.subList(0, 20)) + " and 5 more", l.get(1).getToolTipText());
        assertNull(l.get(4).getToolTipText());
        assertEquals("Finding subdomains", l.get(5).getToolTipText());
        TestJobs.update(d, JobState.RUNNING, "Checking 1 of 3");
        panel.show(List.of(j, d));
        assertEquals("Checking 1 of 3", l.get(5).getToolTipText());
        // A tooltip renders HTML whatever the label says, so server text never starts one.
        TestJobs.update(d, JobState.FAILED, "<html><img src='http://127.0.0.1:9/x'>");
        panel.show(List.of(j, d));
        assertFalse(javax.swing.plaf.basic.BasicHTML.isHTMLString(l.get(5).getToolTipText()));
        assertEquals("<html><img src='http://127.0.0.1:9/x'>", l.get(5).getToolTipText().strip());
    }

    @Test
    void removeFinishedShowsFromTwoFinishedJobsAndClearsThem() throws InterruptedException {
        Job a = waitFor(queue.submit(JobKind.FIND_SUBDOMAINS, "a.example.com", List.of(), false), JobState.FAILED);
        panel.show(queue.jobs());
        assertFalse(buttons().contains(JobsPanel.REMOVE_FINISHED));
        waitFor(queue.submit(JobKind.FIND_SUBDOMAINS, "b.example.com", List.of(), false), JobState.FAILED);
        panel.show(queue.jobs());
        assertTrue(buttons().contains(JobsPanel.REMOVE_FINISHED), buttons().toString());
        button(JobsPanel.REMOVE_FINISHED).doClick(0);
        assertTrue(queue.jobs().isEmpty());
        assertTrue(a.state().finished());
    }
}
