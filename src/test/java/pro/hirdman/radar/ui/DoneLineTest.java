package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobState;
import pro.hirdman.radar.jobs.TestJobs;
import pro.hirdman.radar.model.ResultStore;

class DoneLineTest {

    final ResultStore store = new ResultStore();
    final DoneLine line = new DoneLine();

    void checked(String host, boolean leaks) {
        List<Finding> f = leaks ? List.of(new Finding("k", "high", "tentative", "Leak", "", "", "")) : List.of();
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 1, true, f), Instant.EPOCH);
    }

    @Test
    void aFinishedDomainCheckStaysUntilClosed() {
        checked("a.example.com", true);
        checked("b.example.com", false);
        checked("c.example.com", false);
        Job running = TestJobs.job(JobKind.FIND_AND_CHECK, "example.com", List.of(), JobState.RUNNING, "Checking");
        line.show(List.of(running), store::domain);
        assertFalse(line.panel.isVisible());
        TestJobs.update(running, JobState.DONE, "Done");
        line.show(List.of(running), store::domain);
        assertTrue(line.panel.isVisible());
        assertEquals("Done: example.com, 1 of 3 hosts with leaks.", line.label.getText());
        assertEquals(Boolean.TRUE, line.label.getClientProperty("html.disable"));
        // The job leaving the strip does not take the line with it.
        line.show(List.of(), store::domain);
        assertTrue(line.panel.isVisible());
        line.closeButton.doClick(0);
        assertFalse(line.panel.isVisible());
        line.show(List.of(running), store::domain);
        assertFalse(line.panel.isVisible());
    }

    @Test
    void otherJobsAndFailuresShowNothing() {
        line.show(List.of(TestJobs.job(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), JobState.DONE, "Done"),
                TestJobs.job(JobKind.CHECK_HOSTS, null, List.of("a.example.com"), JobState.DONE, "Done"),
                TestJobs.job(JobKind.FIND_AND_CHECK, "example.com", List.of(), JobState.FAILED, "Failed")), store::domain);
        assertFalse(line.panel.isVisible());
        assertEquals("Done: example.com, 0 of 1 host with leaks.", DoneLine.text("example.com", 0, 1));
    }
}
