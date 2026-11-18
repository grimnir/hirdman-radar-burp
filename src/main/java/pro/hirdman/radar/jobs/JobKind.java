package pro.hirdman.radar.jobs;

public enum JobKind {
    FIND_SUBDOMAINS("Find subdomains"),
    FIND_AND_CHECK("Check for leaks"),
    CHECK_HOSTS("Check hosts");

    private final String label;

    JobKind(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
