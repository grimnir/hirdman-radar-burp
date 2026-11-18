package pro.hirdman.radar.api;

import java.util.List;

/** A poll answer: events after the cursor, the next cursor, and whether the job has ended. */
public record JobPage(List<JobEvent> events, int next, boolean done) {

    public JobPage {
        events = Json.list(events);
    }
}
