package pro.hirdman.radar.jobs;

public enum JobState {
    WAITING, RUNNING, RETRYING, DONE, FAILED, CANCELLED;

    public boolean finished() {
        return this == DONE || this == FAILED || this == CANCELLED;
    }
}
