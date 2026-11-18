package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.sitemap.SiteMapNode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BurpSiteMapTest {

    @Test
    void inScopeHostsWalkTheSiteMapWithoutLoadingIt() {
        List<String> urls = List.of("https://a.example.com/", "https://a.example.com/login", "http://B.example.com:8080/x",
                "https://b.example.com/", "https://out.example.com/", "https://c.example.com/admin", "https://c.example.com/", "not a url",
                "https:///x", "https://:8080/x");
        Set<String> inScope = Set.of("https://a.example.com/login", "http://B.example.com:8080/x", "https://c.example.com/admin",
                "https://:8080/x");
        List<Boolean> matched = new ArrayList<>();
        SiteMap map = fake(SiteMap.class, (m, a) -> {
            SiteMapFilter f = (SiteMapFilter) a[0];
            urls.forEach(u -> matched.add(f.matches(fake(SiteMapNode.class, Map.of("url", u)))));
            return List.of();
        });
        List<String> asked = new ArrayList<>();
        List<String> hosts = BurpSiteMap.inScopeHosts(map, u -> {
            asked.add(u);
            return inScope.contains(u);
        });
        assertEquals(List.of("a.example.com", "b.example.com", "c.example.com"), hosts);
        assertTrue(matched.stream().noneMatch(b -> b), "the filter must not load any item");
        // A host already found in scope is not asked again.
        assertEquals(List.of("https://a.example.com/", "https://a.example.com/login", "http://B.example.com:8080/x",
                "https://out.example.com/", "https://c.example.com/admin"), asked);
    }

    @Test
    void scopeIsAskedAfterTheWalkForOneUrlPerPathSegment() {
        List<String> urls = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            urls.add("https://big.example.com/static/" + i + ".png");
            urls.add("https://cdn.example.net/js/" + i + ".js");
        }
        urls.add("https://big.example.com/app/home");
        for (int i = 0; i < 40; i++) {
            urls.add("https://many.example.com/s" + i + "/x");
        }
        boolean[] walking = {false};
        SiteMap map = fake(SiteMap.class, (m, a) -> {
            SiteMapFilter f = (SiteMapFilter) a[0];
            walking[0] = true;
            urls.forEach(u -> f.matches(fake(SiteMapNode.class, Map.of("url", u))));
            walking[0] = false;
            return List.of();
        });
        List<String> asked = new ArrayList<>();
        List<String> hosts = BurpSiteMap.inScopeHosts(map, u -> {
            assertFalse(walking[0], "Burp holds its site map lock during the walk");
            asked.add(u);
            return u.startsWith("https://big.example.com/app/") || u.equals("https://many.example.com/s39/x");
        });
        assertEquals(List.of("big.example.com"), hosts);
        assertEquals(List.of("https://big.example.com/static/0.png", "https://big.example.com/app/home"),
                asked.stream().filter(u -> u.contains("big.")).toList());
        assertEquals(List.of("https://cdn.example.net/js/0.js"), asked.stream().filter(u -> u.contains("cdn.")).toList());
        assertEquals(BurpSiteMap.SAMPLES, asked.stream().filter(u -> u.contains("many.")).count());
    }

    static final String OFF = "Hirdman Radar: Burp's site map did not take a host, so found hosts stay in the plugin tab only. ";

    final List<String> urls = new ArrayList<>();
    final List<String> lookups = new ArrayList<>();
    final Set<String> present = new HashSet<>();
    final List<Object> added = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
    boolean reject;

    BurpSiteMap siteMap() {
        SiteMap siteMap = fake(SiteMap.class, (m, a) -> {
            if (reject) {
                throw new IllegalArgumentException("no response");
            }
            added.add(a[0]);
            present.add(urls.get(urls.size() - 1));
            return null;
        });
        Logging logging = fake(Logging.class, (m, a) -> {
            if (m.equals("logToError") && a.length == 1 && a[0] instanceof String s) {
                errors.add(s);
                return null;
            }
            return Fakes.DEFAULT;
        });
        MontoyaApi api = fake(MontoyaApi.class, Map.of("siteMap", siteMap, "logging", logging));
        return new BurpSiteMap(api, url -> {
            urls.add(url);
            return fake(HttpRequestResponse.class, Map.of());
        }, wanted -> {
            duringWalk.run();
            lookups.add(new java.util.TreeSet<>(wanted).toString());
            Set<String> hit = new HashSet<>(wanted);
            hit.retainAll(present);
            return hit;
        }, executor);
    }

    java.util.concurrent.Executor executor = Runnable::run;
    Runnable duringWalk = () -> { };

    @Test
    void aWalkInProgressDoesNotHoldUpNewHosts() throws Exception {
        // Found hosts come from the job thread, which must not wait while Burp's site map is walked.
        java.util.concurrent.CountDownLatch walking = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        duringWalk = () -> {
            walking.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        executor = r -> new Thread(r).start();
        BurpSiteMap map = siteMap();
        map.addFound(List.of("a.example.com"));
        assertTrue(walking.await(5, java.util.concurrent.TimeUnit.SECONDS));
        java.util.concurrent.CompletableFuture<Void> next =
                java.util.concurrent.CompletableFuture.runAsync(() -> map.addFound(List.of("b.example.com")));
        try {
            next.get(2, java.util.concurrent.TimeUnit.SECONDS);
        } finally {
            release.countDown();
        }
    }

    @Test
    void foundHostsGatherBeforeAWalk() {
        // During a scan a check arrives every second or so: one walk per few seconds, not one per host.
        List<Runnable> tasks = new java.util.concurrent.CopyOnWriteArrayList<>();
        BurpSiteMap map = new BurpSiteMap(fake(MontoyaApi.class, Map.of()), tasks::add);
        map.addFound(List.of("a.example.com"));
        assertEquals(List.of(), tasks);
        assertEquals(java.time.Duration.ofSeconds(10), BurpSiteMap.GATHER);
    }

    @Test
    void addsOneRootEntryPerHost() {
        siteMap().addFound(List.of("a.example.com", "b.example.com"));
        assertEquals(List.of("https://a.example.com/", "https://b.example.com/"), urls);
        assertEquals(2, added.size());
    }

    @Test
    void aHostAlreadyInTheSiteMapIsLeftAlone() {
        // Burp overwrites a matching item, so an entry without a response would replace real traffic.
        present.add("https://b.example.com/");
        siteMap().addFound(List.of("a.example.com", "b.example.com"));
        assertEquals(List.of("https://a.example.com/"), urls);
        assertEquals(List.of("[https://a.example.com/, https://b.example.com/]"), lookups, "one site map walk per batch");
    }

    @Test
    void eachHostIsLookedAtOncePerSession() {
        BurpSiteMap s = siteMap();
        s.addFound(List.of("a.example.com"));
        s.addFound(List.of("a.example.com"));
        assertEquals(List.of("[https://a.example.com/]"), lookups);
        assertEquals(1, added.size());
    }

    @Test
    void foundHostsWaitForTheBurpThreadAndGoInOneBatch() {
        List<Runnable> queued = new ArrayList<>();
        executor = queued::add;
        BurpSiteMap s = siteMap();
        s.addFound(List.of("a.example.com"));
        s.addFound(List.of("b.example.com"));
        assertEquals(List.of(), urls, "the caller never waits on Burp");
        assertEquals(1, queued.size());
        queued.remove(0).run();
        assertEquals(List.of("[https://a.example.com/, https://b.example.com/]"), lookups);
        assertEquals(List.of("https://a.example.com/", "https://b.example.com/"), urls);
        s.addFound(List.of("c.example.com"));
        assertEquals(1, queued.size());
    }

    @Test
    void siteMapRootsIgnoreThePathAndTheDefaultPort() {
        assertEquals("https://a.example.com/", BurpSiteMap.root("https://a.example.com/login?x=1"));
        assertEquals("https://a.example.com/", BurpSiteMap.root("https://A.example.com:443/"));
        assertEquals("https://a.example.com/", BurpSiteMap.root("https://a.example.com"));
        assertEquals(null, BurpSiteMap.root("http://a.example.com/"));
        assertEquals(null, BurpSiteMap.root("https://a.example.com:8443/"));
        assertEquals(null, BurpSiteMap.root("not a url"));
    }

    @Test
    void rejectedEntryTurnsTheFeatureOffWithOneError() {
        reject = true;
        BurpSiteMap s = siteMap();
        s.addFound(List.of("a.example.com", "b.example.com"));
        s.addFound(List.of("c.example.com"));
        assertEquals(List.of("https://a.example.com/"), urls);
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith(OFF), errors.get(0));
    }

    @Test
    void addSelectedSaysWhatHappened() {
        present.add("https://b.example.com/");
        BurpSiteMap s = siteMap();
        assertEquals("Hirdman Radar: added 1 host to the site map, 1 host was there already",
                s.addSelected(List.of("a.example.com", "b.example.com")));
        assertEquals("Hirdman Radar: added 0 hosts to the site map, 2 hosts were there already",
                s.addSelected(List.of("a.example.com", "b.example.com")));
        present.clear();
        assertEquals("Hirdman Radar: added 2 hosts to the site map", s.addSelected(List.of("a.example.com", "b.example.com")));
    }

    @Test
    void addSelectedTriesEvenAfterAutomaticAddsWereTurnedOff() {
        reject = true;
        BurpSiteMap s = siteMap();
        s.addFound(List.of("a.example.com"));
        assertEquals("Hirdman Radar: Burp did not take the site map entries, see the Errors tab of this extension",
                s.addSelected(List.of("b.example.com")));
        assertEquals(2, errors.size());
        reject = false;
        assertEquals("Hirdman Radar: added 1 host to the site map", s.addSelected(List.of("c.example.com")));
    }
}
