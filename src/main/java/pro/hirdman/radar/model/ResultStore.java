package pro.hirdman.radar.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.menu.ParentDomains;

/** All host rows of the project, keyed by host. Thread-safe; listeners run on the thread that made the change. */
public final class ResultStore {

    private final Map<String, HostResult> rows = new LinkedHashMap<>();
    /** Hosts of each domain in store order, so a domain's rows are found without walking all of them. */
    private final Map<String, Set<String>> byDomain = new HashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<HostResult>> checkListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<List<String>>> foundListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<HostResult>> loginListeners = new CopyOnWriteArrayList<>();

    public void addListener(Runnable onChange) {
        listeners.add(onChange);
    }

    /** Gets every row a check writes. */
    public void addCheckListener(Consumer<HostResult> onChecked) {
        checkListeners.add(onChecked);
    }

    /** Gets the hosts a search adds; hosts already in the store are left out. */
    public void addFoundListener(Consumer<List<String>> onFound) {
        foundListeners.add(onFound);
    }

    /** Gets a row whose login page was just noted. */
    public void addLoginListener(Consumer<HostResult> onLogin) {
        loginListeners.add(onLogin);
    }

    /** Notes a login page on a host that has a row, when it says more than the one already noted. */
    public boolean noteLogin(String host, LoginPage page) {
        Optional<String> h = HostNames.normalize(host);
        if (h.isEmpty()) {
            return false;
        }
        HostResult row;
        synchronized (this) {
            HostResult old = rows.get(h.get());
            if (old == null || !page.betterThan(old.login())) {
                return false;
            }
            row = old.withLogin(page);
            store(row);
        }
        fire();
        loginListeners.forEach(l -> l.accept(row));
        return true;
    }

    /** Adds discovered hosts as Found; rows that already exist are left as they are. */
    public void found(String domain, Collection<String> hosts) {
        Optional<String> d = HostNames.normalize(domain);
        if (d.isEmpty()) {
            return;
        }
        List<String> added = new ArrayList<>();
        synchronized (this) {
            for (String raw : hosts) {
                Optional<String> h = HostNames.normalize(raw);
                if (h.isPresent() && !rows.containsKey(h.get())) {
                    store(HostResult.withoutCounts(h.get(), d.get(), HostStatus.FOUND, null));
                    added.add(h.get());
                }
            }
        }
        if (!added.isEmpty()) {
            fire();
            List<String> found = List.copyOf(added);
            foundListeners.forEach(l -> l.accept(found));
        }
    }

    /** Records a check. A host already in the store keeps its domain and login page; an invalid host is ignored. */
    public Optional<HostResult> apply(String domain, Check e, Instant now) {
        Optional<String> h = HostNames.normalize(e.domain());
        if (h.isEmpty()) {
            return Optional.empty();
        }
        HostResult row;
        synchronized (this) {
            HostResult old = rows.get(h.get());
            String d = old != null ? old.domain() : HostNames.normalize(domain).orElse(ParentDomains.base(h.get()));
            HostResult fresh = row(h.get(), d, e, now);
            row = old == null || old.login() == null ? fresh : fresh.withLogin(old.login());
            store(row);
        }
        fire();
        checkListeners.forEach(l -> l.accept(row));
        return Optional.of(row);
    }

    private static HostResult row(String host, String domain, Check e, Instant now) {
        if (!e.checked()) {
            return HostResult.withoutCounts(host, domain, HostStatus.NOT_CHECKED, now);
        }
        HostStatus status = e.findings().isEmpty() ? HostStatus.CLEAN : HostStatus.CHECKED;
        return new HostResult(host, domain, status, e.stealerCount(), e.hcCorpFound(), e.hcOriginFound(),
                e.dbEmailCount() + e.dbUrlCount(), e.findings(), now, e.breachSources());
    }

    public void remove(Collection<String> hosts) {
        boolean changed = false;
        synchronized (this) {
            for (String raw : hosts) {
                Optional<String> h = HostNames.normalize(raw);
                if (h.isPresent() && drop(h.get())) {
                    changed = true;
                }
            }
        }
        if (changed) {
            fire();
        }
    }

    /** Called on Burp's traffic threads: the name is normalized before the lock is taken. */
    public Optional<HostResult> host(String host) {
        Optional<String> h = HostNames.normalize(host);
        if (h.isEmpty()) {
            return Optional.empty();
        }
        synchronized (this) {
            return Optional.ofNullable(rows.get(h.get()));
        }
    }

    /** When the host was last checked successfully; empty for found hosts and failed checks. */
    public Optional<Instant> lastChecked(String host) {
        return host(host).filter(HostResult::checked).map(HostResult::checkedAt);
    }

    public synchronized List<HostResult> domain(String domain) {
        Set<String> hosts = byDomain.get(domain);
        return hosts == null ? List.of() : hosts.stream().map(rows::get).toList();
    }

    /** Domains in the order their first host arrived. */
    public synchronized List<String> domains() {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        rows.values().forEach(r -> out.add(r.domain()));
        return List.copyOf(out);
    }

    public synchronized List<HostResult> all() {
        return List.copyOf(rows.values());
    }

    /** Puts a fully formed row, as loaded from the project; the caller has validated it. */
    synchronized void put(HostResult row) {
        store(row);
    }

    /** Puts a row under the lock; a row that moves to another domain goes to the end, in both maps alike. */
    private void store(HostResult row) {
        HostResult old = rows.get(row.host());
        if (old != null && !old.domain().equals(row.domain())) {
            drop(row.host());
        }
        rows.put(row.host(), row);
        byDomain.computeIfAbsent(row.domain(), d -> new LinkedHashSet<>()).add(row.host());
    }

    /** Takes a host out of both maps under the lock; returns whether it was there. */
    private boolean drop(String host) {
        HostResult gone = rows.remove(host);
        if (gone == null) {
            return false;
        }
        Set<String> hosts = byDomain.get(gone.domain());
        if (hosts != null && hosts.remove(host) && hosts.isEmpty()) {
            byDomain.remove(gone.domain());
        }
        return true;
    }

    private void fire() {
        listeners.forEach(Runnable::run);
    }
}
