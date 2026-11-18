package pro.hirdman.radar.jobs;

import java.time.Duration;

/** Waits between tries; returns early when the job is cancelled or the user presses Retry now. */
public interface Sleeper {

    void sleep(Duration d, Job job) throws InterruptedException;

    static Sleeper real() {
        return (d, job) -> job.pause(d);
    }
}
