package pro.hirdman.radar.ui;

import static pro.hirdman.radar.jobs.StatusText.count;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import pro.hirdman.radar.model.HostNames;

/** What "Check in-scope hosts" sends, and how many in-scope hosts it skips as checked within the last day. */
record ScopeCheck(List<String> hosts, int recent) {

    static final Duration RECENT = Duration.ofHours(24);

    /** Drops IPs, bad names and the radar server; hosts checked within {@link #RECENT} count as {@code recent}. */
    static ScopeCheck plan(Collection<String> raw, String serverHost, Function<String, Optional<Instant>> lastChecked,
            Instant now) {
        Instant since = now.minus(RECENT);
        String server = serverHost == null ? null : HostNames.normalize(serverHost).orElse(null);
        List<String> hosts = new ArrayList<>();
        int recent = 0;
        for (String h : raw.stream().map(HostNames::normalize).flatMap(Optional::stream).distinct().toList()) {
            if (h.equals(server)) {
                continue;
            }
            if (lastChecked.apply(h).filter(t -> t.isAfter(since)).isPresent()) {
                recent++;
            } else {
                hosts.add(h);
            }
        }
        return new ScopeCheck(List.copyOf(hosts), recent);
    }

    boolean isEmpty() {
        return hosts.isEmpty();
    }

    /** {@code hostsLeft} is the server's hourly allowance for this address, or null when there is none. */
    String question(Integer hostsLeft) {
        StringBuilder q = new StringBuilder("Check ").append(count(hosts.size(), "in-scope host"))
                .append(" from the site map for leaks?");
        if (recent > 0) {
            q.append(' ').append(count(recent, "host")).append(" checked in the last 24 h ").append(recent == 1 ? "is" : "are")
                    .append(" skipped.");
        }
        if (hostsLeft != null) {
            q.append(" Your address can check ").append(count(hostsLeft, "more host")).append(" this hour")
                    .append(hostsLeft < hosts.size() ? "; the rest continue when the limit refills." : ".");
        }
        return q.toString();
    }

    String nothing() {
        if (recent == 0) {
            return "No in-scope host names in the site map.";
        }
        return "Nothing to check: " + count(recent, "in-scope host") + (recent == 1 ? " was" : " were")
                + " checked in the last 24 h.";
    }
}
