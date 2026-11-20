package pro.hirdman.radar.ui;

import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

/** The "Show" chooser above the results table. */
public enum ResultsFilter {
    ALL("All"),
    WITH_LEAKS("With leaks"),
    NEW_SINCE_LAST_CHECK("New since last check"),
    NOT_CHECKED_YET("Not checked yet"),
    FAILED("Check failed"),
    IN_SCOPE("In scope");

    private final String label;

    ResultsFilter(String label) {
        this.label = label;
    }

    boolean keeps(HostResult r, boolean inScope) {
        return switch (this) {
            case ALL -> true;
            case WITH_LEAKS -> r.hasLeaks();
            case NEW_SINCE_LAST_CHECK -> r.newSinceLastCheck();
            case NOT_CHECKED_YET -> r.status() == HostStatus.FOUND;
            case FAILED -> r.status() == HostStatus.NOT_CHECKED;
            case IN_SCOPE -> inScope;
        };
    }

    @Override
    public String toString() {
        return label;
    }
}
