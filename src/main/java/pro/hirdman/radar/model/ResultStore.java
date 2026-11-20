package pro.hirdman.radar.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.menu.ParentDomains;

/** All host rows of the project, keyed by host. Thread-safe; listeners run on the thread that made the change. */
public final class ResultStore {

    private final Map<String, HostResult> rows = new LinkedHashMap<>();
    /** The same rows for {@link #peek}: written under the lock, read without it. */
    private final Map<String, HostResult> index = new ConcurrentHashMap<>();
    /** Hosts of each domain in store order, so a domain's rows are found without walking all of them. */
    private final Map<String, Set<String>> byDomain = new HashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<HostResult>> checkListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<List<String>>> foundListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<HostResult>> loginListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<Set<String>>> domainListeners = new CopyOnWriteArrayList<>();

    public void addListener(Runnable onChange) {
        listeners.add(onChange);
    }

    /** Gets the domains whose rows a change touched, on every change {@link #addListener} hears. */
    public void addDomainListener(Consumer<Set<String>> onChange) {
        domainListeners.add(onChange);
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
        fire(Set.of(row.domain()));
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
            fire(Set.of(d.get()));
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
        fire(Set.of(row.domain()));
        checkListeners.forEach(l -> l.accept(row));
        return Optional.of(row);
    }

    private static HostResult row(String host, String domain, Check e, Instant now) {
        if (!e.checked()) {
            return HostResult.withoutCounts(host, domain, HostStatus.NOT_CHECKED, now);
        }
        HostStatus status = e.findings().isEmpty() ? HostStatus.CLEAN : HostStatus.CHECKED;
        return new HostResult(host, domain, status, Math.max(0, e.stealerCount()), Math.max(0, e.hcCorpFound()),
                Math.max(0, e.hcOriginFound()), sum(e.dbEmailCount(), e.dbUrlCount()), e.findings(), now, e.breachSources());
    }

    /** Server counts are never negative here, and a sum too big for a long stops at the top. */
    private static long sum(long a, long b) {
        long s = Math.max(0, a) + Math.max(0, b);
        return s < 0 ? Long.MAX_VALUE : s;
    }

    public void remove(Collection<String> hosts) {
        Set<String> domains = new LinkedHashSet<>();
        synchronized (this) {
            for (String raw : hosts) {
                HostNames.normalize(raw).map(this::drop).ifPresent(gone -> domains.add(gone.domain()));
            }
        }
        if (!domains.isEmpty()) {
            fire(Set.copyOf(domains));
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

    /**
     * For Burp's traffic threads: no lock and no regex. The name is only lower-cased and stripped of a trailing dot, so
     * anything odd simply finds no row.
     */
    public Optional<HostResult> peek(String host) {
        if (host == null) {
            return Optional.empty();
        }
        HostResult r = index.get(host);
        if (r == null) {
            String h = host.toLowerCase(Locale.ROOT);
            r = index.get(h.endsWith(".") ? h.substring(0, h.length() - 1) : h);
        }
        return Optional.ofNullable(r);
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

    synchronized int size() {
        return rows.size();
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
        index.put(row.host(), row);
        byDomain.computeIfAbsent(row.domain(), d -> new LinkedHashSet<>()).add(row.host());
    }

    /** Takes a host out of both maps under the lock; returns its row, or null when it was not there. */
    private HostResult drop(String host) {
        HostResult gone = rows.remove(host);
        if (gone == null) {
            return null;
        }
        index.remove(host);
        Set<String> hosts = byDomain.get(gone.domain());
        if (hosts != null && hosts.remove(host) && hosts.isEmpty()) {
            byDomain.remove(gone.domain());
        }
        return gone;
    }

    private void fire(Set<String> domains) {
        listeners.forEach(Runnable::run);
        domainListeners.forEach(l -> l.accept(domains));
    }
}
