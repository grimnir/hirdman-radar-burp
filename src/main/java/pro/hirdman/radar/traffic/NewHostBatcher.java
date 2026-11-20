package pro.hirdman.radar.traffic;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import pro.hirdman.radar.model.HostNames;

/**
 * Collects in-scope public host names seen in traffic and hands them out as one batch at most every {@code every}.
 * A host checked or batched within {@code skipCheckedWithin} is skipped. Thread-safe.
 */
public final class NewHostBatcher {

    /** Hosts held between drains; more than this in one minute waits for the next traffic. */
    static final int MAX_PENDING = 1000;

    private final Duration every;
    private final Duration skipCheckedWithin;
    private final Function<String, Optional<Instant>> lastChecked;
    private final Supplier<String> serverHost;
    private final Set<String> pending = new LinkedHashSet<>();
    private final Map<String, Instant> batched = new HashMap<>();
    private Instant lastDrain;

    /** {@code serverHost} is the radar server's host name, read at each drain so a new Server URL counts at once. */
    public NewHostBatcher(Duration every, Duration skipCheckedWithin, Function<String, Optional<Instant>> lastChecked,
            Supplier<String> serverHost) {
        this.every = every;
        this.skipCheckedWithin = skipCheckedWithin;
        this.lastChecked = lastChecked;
        this.serverHost = serverHost;
    }

    public void offer(String host, boolean inScope) {
        if (!inScope) {
            return;
        }
        Optional<String> h = HostNames.normalize(host);
        if (h.isEmpty() || !HostNames.isPublic(h.get())) {
            return;
        }
        synchronized (this) {
            if (pending.size() < MAX_PENDING) {
                pending.add(h.get());
            }
        }
    }

    /**
     * The batch due at {@code now}, or nothing when the last drain was less than {@code every} ago.
     * Store and settings lookups run outside the lock, so traffic threads in {@link #offer} never wait for them.
     */
    public List<String> drain(Instant now) {
        Instant since = now.minus(skipCheckedWithin);
        List<String> candidates;
        synchronized (this) {
            if (lastDrain != null && now.isBefore(lastDrain.plus(every))) {
                return List.of();
            }
            lastDrain = now;
            batched.values().removeIf(t -> !t.isAfter(since));
            candidates = pending.stream().filter(h -> !batched.containsKey(h)).toList();
            pending.clear();
        }
        String server = HostNames.normalize(serverHost.get()).orElse(null);
        List<String> out = candidates.stream()
                .filter(h -> !h.equals(server))
                .filter(h -> lastChecked.apply(h).map(t -> !t.isAfter(since)).orElse(true))
                .toList();
        synchronized (this) {
            out.forEach(h -> batched.put(h, now));
        }
        return out;
    }

    /** Forgets what is pending, as when the setting is turned off. */
    public synchronized void clear() {
        pending.clear();
    }
}
