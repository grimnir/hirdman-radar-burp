package pro.hirdman.radar.model;

import java.util.List;
import java.util.Locale;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.api.ServerEvent.Finding;

/** Ordered lowest first, so compareTo ranks risk. */
public enum Risk {
    NONE(""),
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High");

    private final String label;

    Risk(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** The highest severity among the findings; unknown severities count as none. */
    public static Risk of(List<Finding> findings) {
        Risk top = NONE;
        for (Finding f : findings) {
            Risk r = ofSeverity(f.severity());
            if (r.compareTo(top) > 0) {
                top = r;
            }
        }
        return top;
    }

    public static Risk ofSeverity(@Nullable String severity) {
        return switch (severity == null ? "" : severity.toLowerCase(Locale.ROOT)) {
            case "high" -> HIGH;
            case "medium" -> MEDIUM;
            case "low" -> LOW;
            default -> NONE;
        };
    }
}
