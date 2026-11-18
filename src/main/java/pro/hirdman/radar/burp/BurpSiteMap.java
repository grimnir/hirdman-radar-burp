package pro.hirdman.radar.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.sitemap.SiteMap;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import pro.hirdman.radar.issues.IssuePlanner;
import pro.hirdman.radar.jobs.StatusText;

/**
 * Puts hosts into Target > Site map as entries without a response. Nothing is sent to the hosts. Burp overwrites a matching
 * item, so a host that already has anything in the site map is left alone.
 */
public final class BurpSiteMap {

    /** Distinct first path segments per origin whose first URL is asked about scope. */
    static final int SAMPLES = 32;
    /** Found hosts wait this long for more, so a scan costs one site map walk per few seconds, not one per host. */
    static final Duration GATHER = Duration.ofSeconds(10);

    private record Put(int added, int there) {
    }

    private final MontoyaApi api;
    private final Function<String, HttpRequestResponse> entry;
    private final Function<Set<String>, Set<String>> presentAmong;
    private final Executor executor;
    private final Set<String> seen = new HashSet<>();
    private final Set<String> pending = new LinkedHashSet<>();
    /** Walks and adds take this lock, not {@code this}: hosts handed in meanwhile only wait for the set updates. */
    private final Object walkLock = new Object();
    private boolean drainQueued;
    private volatile boolean off;

    /** Batches of found hosts go to {@code burpThread} after {@link #GATHER}. */
    public BurpSiteMap(MontoyaApi api, Executor burpThread) {
        this(api, url -> HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequestFromUrl(url), null),
                roots -> walk(api, roots),
                CompletableFuture.delayedExecutor(GATHER.toMillis(), TimeUnit.MILLISECONDS, burpThread));
    }

    /** Burp's factories work only inside Burp, so tests pass their own. */
    BurpSiteMap(MontoyaApi api, Function<String, HttpRequestResponse> entry, Function<Set<String>, Set<String>> presentAmong,
            Executor executor) {
        this.api = api;
        this.entry = entry;
        this.presentAmong = presentAmong;
        this.executor = executor;
    }

    /** Hosts the plugin learned about, each looked at once per session, in batches on the executor. */
    public void addFound(Collection<String> hosts) {
        synchronized (this) {
            if (off) {
                return;
            }
            for (String host : hosts) {
                if (seen.add(host)) {
                    pending.add(host);
                }
            }
            if (pending.isEmpty() || drainQueued) {
                return;
            }
            drainQueued = true;
        }
        executor.execute(this::drain);
    }

    private void drain() {
        List<String> batch;
        synchronized (this) {
            drainQueued = false;
            batch = new ArrayList<>(pending);
            pending.clear();
            if (off) {
                return;
            }
        }
        put(batch);
    }

    /** The row menu: tries even when automatic adds are off, and returns the event log line. */
    public String addSelected(Collection<String> hosts) {
        synchronized (this) {
            seen.addAll(hosts);
        }
        Put p = put(List.copyOf(hosts));
        if (p == null) {
            return "Hirdman Radar: Burp did not take the site map entries, see the Errors tab of this extension";
        }
        String line = "Hirdman Radar: added " + StatusText.count(p.added(), "host") + " to the site map";
        return p.there() == 0 ? line
                : line + ", " + StatusText.count(p.there(), "host") + (p.there() == 1 ? " was" : " were") + " there already";
    }

    /** One site map walk for the whole batch; null when Burp refused, which turns automatic adds off. */
    private Put put(List<String> hosts) {
        Set<String> roots = new LinkedHashSet<>();
        hosts.forEach(h -> roots.add(IssuePlanner.baseUrl(h)));
        synchronized (walkLock) {
            try {
                Set<String> there = presentAmong.apply(roots);
                int added = 0;
                for (String url : roots) {
                    if (!there.contains(url)) {
                        api.siteMap().add(entry.apply(url));
                        added++;
                    }
                }
                return new Put(added, there.size());
            } catch (RuntimeException e) {
                off = true;
                api.logging().logToError("Hirdman Radar: Burp's site map did not take a host, so found hosts stay in the plugin tab only. " + e);
                return null;
            }
        }
    }

    /** Which of the roots have items. The filter only takes notes and returns false, so Burp builds no result list. */
    private static Set<String> walk(MontoyaApi api, Set<String> roots) {
        Set<String> hit = new HashSet<>();
        api.siteMap().requestResponses(node -> {
            String root = root(node.url());
            if (root != null && roots.contains(root)) {
                hit.add(root);
            }
            return false;
        });
        return hit;
    }

    /**
     * Hosts in Target > Site map with at least one in-scope item, in site map order. Burp holds its site map lock for the
     * whole walk, so the filter only notes strings (the first URL of each first path segment, up to SAMPLES per origin) and
     * loads no item; scope is asked after the walk. Call it off the EDT.
     */
    public static List<String> inScopeHosts(SiteMap siteMap, Predicate<String> inScope) {
        Map<String, List<String>> samples = new LinkedHashMap<>();
        Set<String> segments = new HashSet<>();
        siteMap.requestResponses(node -> {
            String url = node.url();
            int end = authorityEnd(url);
            if (end > 0) {
                String origin = url.substring(0, end).toLowerCase(Locale.ROOT);
                List<String> urls = samples.computeIfAbsent(origin, o -> new ArrayList<>());
                if (urls.size() < SAMPLES && segments.add(url.substring(0, segmentEnd(url, end)).toLowerCase(Locale.ROOT))) {
                    urls.add(url);
                }
            }
            return false;
        });
        Set<String> found = new LinkedHashSet<>();
        samples.forEach((origin, urls) -> {
            String host = host(origin);
            if (!host.isEmpty() && !found.contains(host) && urls.stream().anyMatch(inScope)) {
                found.add(host);
            }
        });
        return List.copyOf(found);
    }

    /** Where the authority of an http(s) URL ends, or -1 when it has none. Runs for every site map item, so no URI parsing. */
    private static int authorityEnd(String url) {
        int start;
        if (url == null) {
            return -1;
        } else if (url.regionMatches(true, 0, "https://", 0, 8)) {
            start = 8;
        } else if (url.regionMatches(true, 0, "http://", 0, 7)) {
            start = 7;
        } else {
            return -1;
        }
        int end = nextDelimiter(url, start);
        return end == start ? -1 : end;
    }

    private static int segmentEnd(String url, int authorityEnd) {
        return authorityEnd == url.length() ? authorityEnd : nextDelimiter(url, authorityEnd + 1);
    }

    /** The host of a lower-case scheme://authority, without the port. */
    private static String host(String origin) {
        String authority = origin.substring(origin.indexOf("://") + 3);
        int colon = authority.indexOf(':');
        return colon < 0 ? authority : authority.substring(0, colon);
    }

    /** https://host/ for an https URL on the default port, else null. Runs for every site map item, so no URI parsing. */
    static String root(String url) {
        if (url == null || !url.regionMatches(true, 0, "https://", 0, 8)) {
            return null;
        }
        String authority = url.substring(8, nextDelimiter(url, 8)).toLowerCase(Locale.ROOT);
        if (authority.endsWith(":443")) {
            authority = authority.substring(0, authority.length() - 4);
        }
        if (authority.isEmpty() || authority.indexOf(':') >= 0 || authority.indexOf('@') >= 0) {
            return null;
        }
        return "https://" + authority + "/";
    }

    /** The first "/", "?" or "#" at or after {@code from}, else the URL length. */
    private static int nextDelimiter(String url, int from) {
        int end = from;
        while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) {
            end++;
        }
        return end;
    }
}
