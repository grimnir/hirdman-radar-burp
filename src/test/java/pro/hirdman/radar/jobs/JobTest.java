package pro.hirdman.radar.jobs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class JobTest {

    @Test
    void anUpdateThatChangesNothingTellsNoOne() {
        AtomicInteger changes = new AtomicInteger();
        Job j = new Job(JobKind.FIND_AND_CHECK, "example.com", List.of(), false, false, x -> changes.incrementAndGet());
        j.update(JobState.RUNNING, "Checking 1 of 3");
        j.update(JobState.RUNNING, "Checking 1 of 3");
        assertEquals(1, changes.get());
        j.update(JobState.RUNNING, "Checking 2 of 3");
        j.update(JobState.DONE, "Checking 2 of 3");
        assertEquals(3, changes.get());
    }
}
