package pro.hirdman.radar.model;

public enum HostStatus {
    /** Found as a subdomain, never checked. */
    FOUND("Not checked yet"),
    CHECKED("Checked (leaks found)"),
    CLEAN("Checked (nothing found)"),
    /** The account check did not run: counts are unknown, never shown as clean. */
    NOT_CHECKED("Check failed");

    private final String label;

    HostStatus(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
