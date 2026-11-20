package pro.hirdman.radar.ui;

import java.util.Optional;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.api.Meta.Limits;

/** The limits line under the results table; none when the server sets no hourly limit. */
public final class LimitsText {

    private LimitsText() {
    }

    public static Optional<String> of(@Nullable Limits l) {
        if (l == null || l.hostsPerHour() <= 0) {
            return Optional.empty();
        }
        return Optional.of("Free limits: up to " + l.maxHosts() + " hosts per check and " + l.hostsPerHour()
                + " per hour from your address.");
    }
}
