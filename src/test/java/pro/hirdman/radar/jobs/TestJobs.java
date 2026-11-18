package pro.hirdman.radar.jobs;

import java.time.Duration;
import java.util.List;

/** Jobs in a given state for UI tests, outside any queue. */
public final class TestJobs {

    private TestJobs() {
    }

    public static Job job(JobKind kind, String domain, List<String> hosts, JobState state, String status) {
        Job j = new Job(kind, domain, hosts, false, false, x -> { });
        j.update(state, status);
        return j;
    }

    public static void update(Job j, JobState state, String status) {
        j.update(state, status);
    }

    public static void pause(Job j, Duration d) throws InterruptedException {
        j.pause(d);
    }

    public static Job recheck(List<String> hosts) {
        return new Job(JobKind.CHECK_HOSTS, null, hosts, false, true, x -> { });
    }
}
