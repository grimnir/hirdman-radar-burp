package pro.hirdman.radar.ui;

import java.util.Optional;
import pro.hirdman.radar.api.Meta.Limits;

/** The limits line under the results table; none when the server sets no hourly limit. */
public final class LimitsText {

    private LimitsText() {
    }

    public static Optional<String> of(Limits l) {
        if (l == null || l.hostsPerHour() <= 0) {
            return Optional.empty();
        }
        return Optional.of("Without a key: up to " + l.maxHosts() + " hosts per check and " + l.hostsPerHour()
                + " hosts per hour from your address.");
    }
}
