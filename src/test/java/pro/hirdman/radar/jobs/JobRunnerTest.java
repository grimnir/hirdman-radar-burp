package pro.hirdman.radar.jobs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.jobs.FakeRadar.check;
import static pro.hirdman.radar.jobs.FakeRadar.done;
import static pro.hirdman.radar.jobs.FakeRadar.error;
import static pro.hirdman.radar.jobs.FakeRadar.ev;
import static pro.hirdman.radar.jobs.FakeRadar.http;
import static pro.hirdman.radar.jobs.FakeRadar.page;
import static pro.hirdman.radar.jobs.FakeRadar.rootCheck;
import static pro.hirdman.radar.jobs.FakeRadar.unreachable;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.JobEvent;
import pro.hirdman.radar.api.JobPage;
import pro.hirdman.radar.api.JobRequest;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.SubdomainList;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.ResultStore;

@Timeout(10)
class JobRunnerTest {

    static final String OFFLINE = "Cannot reach scan.hirdman.pro. The plugin needs internet access, directly or through Burp's upstream proxy. Behind a proxy that re-signs HTTPS, turn off the certificate check in Settings > Extensions > Hirdman Radar.";
    static final String SAVED = ". Not rescanned: the domain was scanned less than an hour ago, so that scan is shown.";

    final FakeRadar radar = new FakeRadar();
    final ResultStore store = new ResultStore();
    final MetaGate gate = new MetaGate();
    final List<Duration> pauses = new CopyOnWriteArrayList<>();
    final List<String> events = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    final List<String> statuses = new CopyOnWriteArrayList<>();
    JobRunner.RunOptions options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, false, 5, true);
    final AtomicLong clock = new AtomicLong();

    JobRunner runner() {
        return runner(() -> radar);
    }

    JobRunner runner(Supplier<Radar> r) {
        return runner(r, (d, job) -> pauses.add(d), () -> options);
    }

    /** Requests run on the test thread; the clock moves only by the pauses. */
    JobRunner runner(Supplier<Radar> r, Sleeper sleeper, Supplier<JobRunner.RunOptions> o) {
        Sleeper ticking = (d, job) -> {
            clock.addAndGet(d.toNanos());
            sleeper.sleep(d, job);
        };
        return new JobRunner(server -> r.get(), store, gate, ticking, o, events::add, errors::add, () -> 0.5, clock::get,
                Runnable::run);
    }

    Job job(JobKind kind, String domain, List<String> hosts, boolean rescan) {
        return new Job(kind, domain, hosts, rescan, false, j -> statuses.add(j.status()));
    }

    Job domainJob() {
        return job(JobKind.FIND_AND_CHECK, "example.com", List.of(), false);
    }

    List<String> run(Job j) {
        return runner().run(j, j.token());
    }

    static final String OFF = "Failed: Private project: nothing was sent. The switch is at the bottom of the Hirdman Radar tab.";

    @Test
    void aProjectTurnedOffFailsTheJobBeforeAnyRequest() {
        options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, false, 5, true, true);
        java.util.concurrent.atomic.AtomicInteger asked = new java.util.concurrent.atomic.AtomicInteger();
        Job j = domainJob();
        assertEquals(List.of(), runner(() -> {
            asked.incrementAndGet();
            return radar;
        }).run(j, j.token()));
        assertEquals(JobState.FAILED, j.state());
        assertEquals(OFF, j.status());
        assertEquals(0, asked.get());
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void settingsThatCannotBeReadFailTheJobInsteadOfTheWorker() {
        JobRunner r = runner(() -> radar, (d, job) -> pauses.add(d), () -> {
            throw new IllegalStateException("settings gone");
        });
        Job j = domainJob();
        assertEquals(List.of(), r.run(j, j.token()));
        assertEquals(JobState.FAILED, j.state());
        assertTrue(j.status().startsWith("Failed: Unexpected error"), j.status());
        assertTrue(errors.get(0).contains("settings gone"), errors.toString());
    }

    static JobEvent started() {
        return ev("scan_started", "{\"scan_id\":\"s\",\"domain\":\"example.com\",\"mode\":\"basic\"}");
    }

    static List<String> hosts(int from, int to) {
        return IntStream.range(from, to).mapToObj(i -> "h" + i + ".example.com").toList();
    }

    static JobEvent[] checks(List<String> hosts) {
        return hosts.stream().map(h -> check(h, true)).toArray(JobEvent[]::new);
    }

    static JobEvent[] plus(JobEvent[] a, JobEvent b) {
        List<JobEvent> l = new ArrayList<>(List.of(a));
        l.add(b);
        return l.toArray(JobEvent[]::new);
    }

    @Test
    void domainJobFillsStoreAndEndsDone() {
        radar.polls.add(page(3, false, started(), rootCheck("example.com"), check("vpn.example.com", true, "high")));
        radar.polls.add(page(4, true, done(1, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.DONE, j.state());
        assertEquals("Done: 2 hosts, 1 with leaks", j.status());
        assertEquals(List.of("example.com", "vpn.example.com"), store.domain("example.com").stream().map(HostResult::host).toList());
        assertEquals(List.of(Duration.ofSeconds(2)), pauses);
        assertEquals(List.of("meta", "start {\"domain\":\"example.com\",\"rescan\":false}", "poll j1 0", "poll j1 3"), radar.calls);
        assertTrue(events.contains("Hirdman Radar: finished example.com, 2 hosts, 1 with leaks"), events.toString());
        assertTrue(statuses.contains("Finding subdomains"), statuses.toString());
    }

    @Test
    void pollUsesNextAsAfter() {
        radar.polls.add(page(3, false, started()));
        radar.polls.add(page(7, false, rootCheck("example.com")));
        radar.polls.add(page(7, true, done(0, 0)));
        run(domainJob());
        assertEquals(List.of(0, 3, 7), radar.pollAfters);
    }

    @Test
    void unreachableStartRetriesThenFails() {
        for (int i = 0; i < 5; i++) {
            radar.starts.add(unreachable());
        }
        Job j = domainJob();
        run(j);
        assertEquals(List.of(Duration.ofSeconds(2), Duration.ofSeconds(4), Duration.ofSeconds(8), Duration.ofSeconds(16)), pauses);
        assertEquals(JobState.FAILED, j.state());
        assertEquals("Failed: " + OFFLINE, j.status());
        assertTrue(statuses.contains("Server unreachable. Retrying in 2 s, attempt 1 of 5."), statuses.toString());
        assertTrue(events.contains("Hirdman Radar: example.com failed: " + OFFLINE), events.toString());
    }

    @Test
    void failureEventsAreMarked() {
        for (int i = 0; i < 5; i++) {
            radar.starts.add(unreachable());
        }
        run(domainJob());
        assertEquals(List.of("Hirdman Radar: example.com failed: " + OFFLINE), events.stream().filter(JobRunner::isFailure).toList());
        assertTrue(!JobRunner.isFailure("Hirdman Radar: finished example.com, 3 hosts, 1 with leaks"));
        assertTrue(!JobRunner.isFailure("Hirdman Radar: queued leak check for example.com"));
        assertTrue(!JobRunner.isFailure(null));
    }

    @Test
    void deleteWithoutAServerDoesNothing() {
        JobRunner.deleteQuietly(null, "j1", Duration.ofSeconds(1));
    }

    @Test
    void runOptionsComeFromTheSettings() {
        assertEquals(new JobRunner.RunOptions(URI.create("https://radar.example.com:8443"), null, true, 3, false),
                JobRunner.RunOptions.of(new pro.hirdman.radar.config.Options("https://radar.example.com:8443/", true, false,
                        pro.hirdman.radar.model.Risk.LOW, true, false, false, 3, true)));
        assertEquals(new JobRunner.RunOptions(null, "Server URL must start with https://", false, 5, true),
                JobRunner.RunOptions.of(new pro.hirdman.radar.config.Options("http://radar.example.com", true, false,
                        pro.hirdman.radar.model.Risk.LOW, true, false, true, 5, false)));
        assertEquals(new JobRunner.RunOptions(URI.create("https://radar.example.com"), null, false, 3, false, true),
                JobRunner.RunOptions.of(new pro.hirdman.radar.config.Options("https://radar.example.com", true, false,
                        pro.hirdman.radar.model.Risk.LOW, true, false, false, 3, false, true)));
    }

    @Test
    void pollFailureRetriesSameAfter() {
        radar.polls.add(page(3, false, started()));
        radar.polls.add(unreachable());
        radar.polls.add(page(4, true, rootCheck("example.com"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(List.of(0, 3, 3), radar.pollAfters);
        assertEquals(JobState.DONE, j.state());
    }

    @Test
    void attemptsResetAfterASuccess() {
        // Each success resets the count: four failed starts, then a failed first poll, then four more after a good page.
        for (int i = 0; i < 4; i++) {
            radar.starts.add(unreachable());
        }
        radar.polls.add(unreachable());
        radar.polls.add(page(1, false, started()));
        for (int i = 0; i < 4; i++) {
            radar.polls.add(unreachable());
        }
        radar.polls.add(page(2, true, rootCheck("example.com"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.DONE, j.state(), j.status());
    }

    @Test
    void lostDomainJobResumesWithTheHostsLeft() {
        radar.polls.add(page(2, false, rootCheck("example.com"), check("vpn.example.com", true, "high")));
        radar.polls.add(http(404, "{\"error\":\"job not found or expired\"}"));
        radar.subdomains.add(subdomains("vpn.example.com", "dev.example.com", "mail.example.com"));
        radar.polls.add(page(3, true, check("dev.example.com", true), check("mail.example.com", true), done(2, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(List.of(JobRequest.ofDomain("example.com", false), JobRequest.ofHosts(List.of("dev.example.com", "mail.example.com"))),
                radar.started);
        assertTrue(radar.calls.contains("subdomains example.com false"), radar.calls.toString());
        assertEquals(JobState.DONE, j.state());
        assertEquals("Done: 4 hosts, 1 with leaks", j.status());
        assertEquals(4, store.all().size());
        assertTrue(events.contains("Hirdman Radar: example.com was interrupted on the server, resuming"), events.toString());
        assertEquals(List.of(0, 2, 0), radar.pollAfters);
    }

    @Test
    void lostDomainJobWithEverythingCheckedEndsDone() {
        radar.polls.add(page(2, true, rootCheck("example.com"), check("vpn.example.com", true)));
        radar.subdomains.add(subdomains("vpn.example.com"));
        Job j = domainJob();
        run(j);
        assertEquals(1, radar.started.size());
        assertEquals("Done: 2 hosts, 0 with leaks", j.status());
        assertTrue(events.stream().noneMatch(e -> e.contains("resuming")), events.toString());
    }

    @Test
    void resumedDomainJobIsBatched() {
        List<String> subs = hosts(0, 60);
        radar.polls.add(http(404, "{\"error\":\"job not found or expired\"}"));
        radar.subdomains.add(subdomains(subs.toArray(String[]::new)));
        List<String> all = new ArrayList<>(List.of("example.com"));
        all.addAll(subs);
        radar.polls.add(page(50, true, plus(checks(all.subList(0, 50)), done(50, 0))));
        radar.polls.add(page(11, true, plus(checks(all.subList(50, 61)), done(11, 0))));
        Job j = domainJob();
        run(j);
        assertEquals(List.of(50, 11), radar.started.stream().skip(1).map(r -> r.hosts().size()).toList());
        assertEquals("Done: 61 hosts, 0 with leaks", j.status());
    }

    @Test
    void resumedHostsAreNormalizedAndAnErrorThereFails() {
        radar.polls.add(http(404, "{\"error\":\"job not found or expired\"}"));
        radar.subdomains.add(subdomains("DEV.example.com.", "bad host"));
        radar.polls.add(page(2, true, error("All services unavailable"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(JobRequest.ofHosts(List.of("example.com", "dev.example.com")), radar.started.get(1));
        assertEquals("Failed: All services unavailable", j.status());
    }

    static SubdomainList subdomains(String... hosts) {
        return new SubdomainList("example.com", List.of(hosts).stream().map(h -> new SubdomainList.Subdomain(h, 1)).toList(), List.of());
    }

    @Test
    void jobEndedWithoutDoneResumesRemainingHosts() {
        List<String> hosts = List.of("a.example.com", "b.example.com", "c.example.com");
        radar.polls.add(page(2, true, check("a.example.com", true), error("scan cancelled")));
        radar.polls.add(page(3, true, check("b.example.com", true), check("c.example.com", true), done(2, 0)));
        Job j = job(JobKind.CHECK_HOSTS, null, hosts, false);
        run(j);
        assertEquals(List.of(JobRequest.ofHosts(hosts), JobRequest.ofHosts(List.of("b.example.com", "c.example.com"))), radar.started);
        assertEquals(JobState.DONE, j.state());
        assertEquals("Done: 3 hosts, 0 with leaks", j.status());
    }

    @Test
    void secondLossFails() {
        radar.polls.add(page(1, true, error("scan cancelled")));
        radar.subdomains.add(subdomains());
        radar.polls.add(page(1, true, error("scan cancelled")));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.FAILED, j.state());
        assertEquals("Failed: scan cancelled", j.status());
        assertEquals(2, radar.started.size());
        assertTrue(events.contains("Hirdman Radar: example.com failed: scan cancelled"), events.toString());
    }

    @Test
    void secondLossWithoutErrorNamesTheServer() {
        radar.polls.add(page(0, true));
        radar.subdomains.add(subdomains());
        radar.polls.add(http(404, "{\"error\":\"job not found or expired\"}"));
        Job j = domainJob();
        run(j);
        assertEquals("Failed: The server stopped the job", j.status());
    }

    @Test
    void errorThenDoneFailsWithoutResume() {
        radar.polls.add(page(2, true, error("All services unavailable"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.FAILED, j.state());
        assertEquals("Failed: All services unavailable", j.status());
        assertEquals(1, radar.started.size());
    }

    @Test
    void hostsSplitIntoBatchesOfMaxHosts() {
        List<String> all = hosts(0, 120);
        radar.polls.add(page(51, true, plus(checks(all.subList(0, 50)), done(50, 0))));
        radar.polls.add(page(51, true, plus(checks(all.subList(50, 100)), done(50, 0))));
        radar.polls.add(page(21, true, plus(checks(all.subList(100, 120)), done(20, 0))));
        Job j = job(JobKind.CHECK_HOSTS, null, all, false);
        run(j);
        assertEquals(List.of(50, 50, 20), radar.started.stream().map(r -> r.hosts().size()).toList());
        assertEquals(all.subList(50, 100), radar.started.get(1).hosts());
        assertEquals(JobState.DONE, j.state());
        assertEquals("Done: 120 hosts, 0 with leaks", j.status());
        assertEquals(List.of("example.com"), store.domains());
        assertEquals("120 hosts", j.label());
    }

    @Test
    void hourlyLimitWaitsAndContinuesBatches() {
        List<String> all = hosts(0, 60);
        radar.starts.add("j1");
        radar.starts.add(http(429, "{\"error\":\"hourly limit without a key: 300 hosts per hour\"}", "Retry-After", "2400"));
        radar.starts.add("j2");
        radar.polls.add(page(51, true, plus(checks(all.subList(0, 50)), done(50, 0))));
        radar.polls.add(page(11, true, plus(checks(all.subList(50, 60)), done(10, 0))));
        Job j = job(JobKind.CHECK_HOSTS, null, all, false);
        run(j);
        assertTrue(statuses.contains("Hourly limit reached. Continues in 40 min."), statuses.toString());
        assertTrue(pauses.contains(Duration.ofSeconds(2400)), pauses.toString());
        assertEquals(JobState.DONE, j.state());
        assertEquals(60, store.all().size());
        assertEquals(List.of(50, 10, 10), radar.started.stream().map(r -> r.hosts().size()).toList());
    }

    @Test
    void http401FailsWithoutRetry() {
        radar.starts.add(http(401, "{\"error\":\"unauthorized\"}"));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.FAILED, j.state());
        assertEquals("Failed: The radar server is not taking checks right now. Try again later.", j.status());
        assertEquals(1, radar.started.size());
        assertTrue(pauses.isEmpty());
    }

    @Test
    void savedScanIsNamedWhenRescanWasAsked() {
        JobEvent cached = ev("scan_started", "{\"cached\":\"true\",\"domain\":\"example.com\",\"mode\":\"basic\",\"scan_id\":\"x\"}");
        radar.polls.add(page(3, true, cached, rootCheck("example.com"), done(0, 0)));
        Job asked = job(JobKind.FIND_AND_CHECK, "example.com", List.of(), true);
        run(asked);
        assertEquals("Done: 1 host, 0 with leaks" + SAVED, asked.status());
        assertEquals(JobRequest.ofDomain("example.com", true), radar.started.get(0));

        // Without rows the plain job scans again instead of taking the repeat path.
        store.remove(List.of("example.com"));
        radar.polls.add(page(3, true, cached, rootCheck("example.com"), done(0, 0)));
        Job plain = domainJob();
        run(plain);
        assertEquals("Done: 1 host, 0 with leaks", plain.status());
    }

    @Test
    void alwaysRescanAsksForAFreshScan() {
        options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, true, 5, true);
        radar.polls.add(page(1, true, rootCheck("example.com"), done(0, 0)));
        run(domainJob());
        assertEquals(JobRequest.ofDomain("example.com", true), radar.started.get(0));
    }

    @Test
    void findSubdomainsFillsFound() {
        radar.subdomains.add(http(503, "", "Retry-After", "30"));
        radar.subdomains.add(new SubdomainList("example.com", List.of(new SubdomainList.Subdomain("vpn.example.com", 3),
                new SubdomainList.Subdomain("dev.example.com", 1), new SubdomainList.Subdomain("blog.example.com", 0)), List.of()));
        Job j = job(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false);
        run(j);
        assertEquals(List.of(Duration.ofSeconds(30)), pauses);
        assertEquals(List.of("vpn.example.com", "dev.example.com", "blog.example.com"),
                store.domain("example.com").stream().map(HostResult::host).toList());
        assertTrue(store.all().stream().allMatch(r -> r.status() == HostStatus.FOUND));
        assertEquals(JobState.DONE, j.state());
        assertEquals("Done: 3 hosts", j.status());
        assertTrue(events.contains("Hirdman Radar: finished example.com, 3 hosts"), events.toString());
    }

    @Test
    void returnsNotCheckedHostsForRecheck() {
        radar.polls.add(page(3, true, rootCheck("example.com"), check("x.example.com", false), done(1, 1)));
        Job j = domainJob();
        assertEquals(List.of("x.example.com"), run(j));
        assertEquals("Done: 2 hosts, 0 with leaks, 1 failed", j.status());

        radar.polls.add(page(1, true, check("x.example.com", false), done(1, 1)));
        Job recheck = new Job(JobKind.CHECK_HOSTS, null, List.of("x.example.com"), false, true, j2 -> { });
        assertEquals(List.of(), run(recheck));
        assertEquals("Re-check failed", recheck.label());

        options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, false, 5, false);
        radar.polls.add(page(3, true, check("x.example.com", false), done(1, 1)));
        assertEquals(List.of(), run(domainJob()));
    }

    @Test
    void malformedEventIsSkipped() {
        radar.polls.add(page(3, true, ev("progress", "\"x\""), rootCheck("example.com"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: Malformed progress event"), errors.toString());
        assertEquals(JobState.DONE, j.state());
    }

    @Test
    void malformedEventsAreLoggedAFewTimesPerJob() {
        JobEvent[] bad = IntStream.range(0, 10).mapToObj(i -> ev("progress", "\"x\"")).toArray(JobEvent[]::new);
        radar.polls.add(page(12, true, plus(plus(bad, rootCheck("example.com")), done(0, 0))));
        Job j = domainJob();
        run(j);
        assertEquals(4, errors.size(), errors.toString());
        assertTrue(errors.subList(0, 3).stream().allMatch(e -> e.startsWith("Hirdman Radar: Malformed progress event")),
                errors.toString());
        assertEquals("Hirdman Radar: more malformed events from the server were skipped without a note", errors.get(3));
        assertEquals(JobState.DONE, j.state());
    }

    @Test
    void queueAndProgressShowInStatus() {
        radar.polls.add(page(1, false, ev("queued", "{\"position\":2,\"eta_sec\":40}")));
        radar.polls.add(page(2, false, ev("progress", "{\"checked\":37,\"total\":120}")));
        radar.polls.add(page(3, true, done(0, 0)));
        run(domainJob());
        assertTrue(statuses.contains("Server queue: #2, about 40 s"), statuses.toString());
        assertTrue(statuses.contains("Checking 37 of 120, about 56 s left"), statuses.toString());
    }

    @Test
    void invalidServerUrlFails() {
        options = new JobRunner.RunOptions(null, "Server URL must start with https://", false, 5, true);
        Job j = domainJob();
        run(j);
        assertEquals("Failed: Server URL in Settings > Extensions > Hirdman Radar is not valid. Server URL must start with https://",
                j.status());
        assertTrue(radar.calls.isEmpty());
    }

    @Test
    void metaIsAskedOncePerServerAndOldPluginIsReported() {
        radar.metas.add(new Meta(1, "9.0.0", "anonymous", new Meta.Limits(50, 1.5, 300), null));
        radar.polls.add(page(1, true, done(0, 0)));
        radar.polls.add(page(1, true, done(0, 0)));
        run(domainJob());
        run(domainJob());
        assertEquals(1, radar.calls.stream().filter("meta"::equals).count());
        assertEquals(List.of("Hirdman Radar: this plugin is older than the server expects (9.0.0)"), errors);
    }

    @Test
    void unexpectedErrorFailsTheJob() {
        Job j = domainJob();
        run(j);
        assertEquals(JobState.FAILED, j.state());
        assertTrue(j.status().startsWith("Failed: Unexpected error"), j.status());
        assertEquals(1, errors.size());
    }

    @Test
    void jobKeepsOnlyValidDistinctHosts() {
        Job j = job(JobKind.CHECK_HOSTS, null, List.of("A.example.com", "a.example.com.", "bad host", "10.0.0.1"), false);
        assertEquals(List.of("a.example.com"), j.hosts());
        assertEquals("1 host", j.label());
    }

    @Test
    void lostBatchWithEveryHostCheckedIsNotResent() {
        radar.polls.add(page(2, true, check("a.example.com", true), check("b.example.com", true)));
        Job j = job(JobKind.CHECK_HOSTS, null, List.of("a.example.com", "b.example.com"), false);
        run(j);
        assertEquals(1, radar.started.size());
        assertEquals("Done: 2 hosts, 0 with leaks", j.status());
        assertTrue(events.stream().noneMatch(e -> e.contains("resuming")), events.toString());
    }

    @Test
    void emptyPageIsPolledAgainAfterAPause() {
        // A server that answers an empty page at once, again and again, must not get a request loop.
        radar.polls.add(page(0, false));
        radar.polls.add(page(2, true, rootCheck("example.com"), done(0, 0)));
        run(domainJob());
        assertEquals(List.of(JobRunner.POLL_PAUSE), pauses);
        assertEquals(List.of(0, 0), radar.pollAfters);
    }

    @Test
    void rateLimitWaitsAddUpOverTheJob() {
        String hourly = "{\"error\":\"hourly limit without a key: 300 hosts per hour\"}";
        radar.starts.add(http(429, hourly, "Retry-After", "3600"));
        radar.starts.add(http(429, hourly, "Retry-After", "3600"));
        Job j = domainJob();
        run(j);
        assertEquals(List.of(Duration.ofHours(1)), pauses);
        assertEquals("Failed: Rate limited by the server for over 70 minutes", j.status());
    }

    @Test
    void alwaysRescanAppliesToSubdomainSearch() {
        options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, true, 5, true);
        radar.subdomains.add(new SubdomainList("example.com", List.of(), List.of()));
        run(job(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false));
        assertTrue(radar.calls.contains("subdomains example.com true"), radar.calls.toString());
    }

    @Test
    void foundHostsAreNormalizedAndDistinct() {
        radar.subdomains.add(new SubdomainList("example.com", List.of(new SubdomainList.Subdomain("vpn.example.com", 3),
                new SubdomainList.Subdomain("VPN.example.com.", 3), new SubdomainList.Subdomain("bad host", 1),
                new SubdomainList.Subdomain("dev.example.com", 1)), List.of()));
        Job j = job(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false);
        run(j);
        assertEquals("Done: 2 hosts", j.status());
    }

    @Test
    void failedJobAsksNoRecheck() {
        radar.polls.add(page(3, true, check("x.example.com", false), error("scan cancelled"), done(1, 1)));
        Job j = domainJob();
        assertEquals(List.of(), run(j));
        assertEquals(JobState.FAILED, j.state());
    }

    @Test
    void notCheckedHostWithAFindingIsNoLeak() {
        radar.polls.add(page(3, true, rootCheck("example.com"), check("x.example.com", false, "high"), done(1, 1)));
        Job j = domainJob();
        run(j);
        assertEquals("Done: 2 hosts, 0 with leaks, 1 failed", j.status());
    }

    @Test
    void serverProblemFailsEvenWithAServer() {
        options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), "Server URL must not contain a path", false, 5,
                true);
        Job j = domainJob();
        run(j);
        assertEquals("Failed: Server URL in Settings > Extensions > Hirdman Radar is not valid. Server URL must not contain a path",
                j.status());
        assertTrue(radar.calls.isEmpty());
    }

    @Test
    void cancelledRunReportsNothing() {
        Job j = domainJob();
        j.markCancelled(false);
        runner(() -> {
            throw new IllegalStateException("boom");
        }).run(j, j.token());
        assertEquals(List.of(), events);
        assertEquals(List.of(), errors);
        assertEquals(JobState.CANCELLED, j.state());
    }

    @Test
    void cancelDuringStartDeletesTheNewServerJob() {
        Job j = domainJob();
        Radar cancelling = new Radar() {
            @Override
            public Meta meta() throws ApiException {
                return radar.meta();
            }

            @Override
            public SubdomainList subdomains(String domain, boolean rescan) throws ApiException {
                return radar.subdomains(domain, rescan);
            }

            @Override
            public String startJob(JobRequest request) throws ApiException {
                String id = radar.startJob(request);
                j.markCancelled(false);
                return id;
            }

            @Override
            public JobPage poll(String jobId, int after) throws ApiException {
                return radar.poll(jobId, after);
            }

            @Override
            public void deleteJob(String jobId, Duration timeout) throws ApiException {
                radar.deleteJob(jobId, timeout);
            }
        };
        runner(() -> cancelling).run(j, j.token());
        assertEquals(List.of("j1"), radar.deleted);
        assertTrue(radar.pollAfters.isEmpty());
        assertEquals(List.of(), events);
    }

    @Test
    void hostJobEventsNameTheHostCount() {
        radar.polls.add(page(3, true, check("a.example.com", true, "high"), check("b.example.com", true), done(2, 0)));
        run(job(JobKind.CHECK_HOSTS, null, List.of("a.example.com", "b.example.com"), false));
        assertEquals(List.of("Hirdman Radar: finished leak check of 2 hosts, 1 with leaks"), events);

        events.clear();
        radar.polls.add(page(1, true, check("c.example.com", true), done(1, 0)));
        run(new Job(JobKind.CHECK_HOSTS, null, List.of("c.example.com"), false, true, j -> { }));
        assertEquals(List.of("Hirdman Radar: finished re-check of 1 host, 0 with leaks"), events);

        events.clear();
        radar.starts.add(http(401, "{\"error\":\"unauthorized\"}"));
        run(job(JobKind.CHECK_HOSTS, null, List.of("d.example.com", "e.example.com"), false));
        assertEquals(List.of("Hirdman Radar: leak check of 2 hosts failed: The radar server is not taking checks right now. Try again later."),
                events);
    }

    @Test
    void queuedEventNamesTheJob() {
        JobRunner r = runner();
        r.queued(job(JobKind.FIND_AND_CHECK, "Example.com", List.of(), false));
        r.queued(job(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false));
        r.queued(job(JobKind.CHECK_HOSTS, null, hosts(0, 7), false));
        r.queued(new Job(JobKind.CHECK_HOSTS, null, List.of("a.example.com"), false, true, j -> { }));
        assertEquals(List.of("Hirdman Radar: queued leak check for example.com", "Hirdman Radar: queued subdomain search for example.com",
                "Hirdman Radar: queued leak check of 7 hosts", "Hirdman Radar: queued re-check of 1 host"), events);
    }

    @Test
    void jobCancelledAtTheEndAsksNoRecheck() {
        radar.polls.add(page(3, true, rootCheck("example.com"), check("x.example.com", false), done(1, 1)));
        // Cancels once the last page's checks are in, before the run reaches its end.
        Job j = new Job(JobKind.FIND_AND_CHECK, "example.com", List.of(), false, false, job -> { });
        store.addCheckListener(row -> {
            if (row.host().equals("x.example.com")) {
                j.markCancelled(false);
            }
        });
        assertEquals(List.of(), run(j));
        assertEquals(JobState.CANCELLED, j.state());
        assertEquals(List.of(), events);
    }

    void checkedAgo(String host, boolean ok, Duration ago) {
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 0, ok, List.of()), Instant.now().minus(ago));
    }

    @Test
    void freshHostsAreNotSent() {
        checkedAgo("a.example.com", true, Duration.ofHours(1));
        checkedAgo("b.example.com", true, Duration.ofHours(25));
        checkedAgo("c.example.com", false, Duration.ofMinutes(1));
        radar.polls.add(page(2, true, check("b.example.com", true), check("c.example.com", true), done(2, 0)));
        Job j = job(JobKind.CHECK_HOSTS, null, List.of("a.example.com", "b.example.com", "c.example.com"), false);
        run(j);
        assertEquals(List.of(JobRequest.ofHosts(List.of("b.example.com", "c.example.com"))), radar.started);
        assertEquals("Done: 2 hosts, 0 with leaks. 1 host checked in the last 24 h was skipped.", j.status());
        assertTrue(statuses.stream().anyMatch(t -> t.startsWith("Checking 2 of 2")), statuses.toString());
        assertTrue(statuses.stream().noneMatch(t -> t.contains(" of 3")), statuses.toString());
    }

    @Test
    void allFreshSendsNothing() {
        checkedAgo("a.example.com", true, Duration.ofHours(1));
        Job j = job(JobKind.CHECK_HOSTS, null, List.of("a.example.com"), false);
        assertEquals(List.of(), run(j));
        assertEquals(List.of(), radar.calls);
        assertEquals(JobState.DONE, j.state());
        assertEquals(StatusText.allFresh(1), j.status());
        assertTrue(events.contains("Hirdman Radar: finished leak check of 1 host. " + StatusText.allFresh(1)), events.toString());
    }

    @Test
    void checkAgainSendsFreshHosts() {
        checkedAgo("a.example.com", true, Duration.ofMinutes(1));
        radar.polls.add(page(1, true, check("a.example.com", true), done(1, 0)));
        Job j = new Job(JobKind.CHECK_HOSTS, null, List.of("a.example.com"), false, false, true, x -> { });
        run(j);
        // Asked for by the user, so the server's shared 24-hour result is skipped too.
        assertEquals(List.of(JobRequest.ofHosts(List.of("a.example.com"), true)), radar.started);
        assertEquals("Done: 1 host, 0 with leaks", j.status());
    }

    @Test
    void automaticChecksTakeTheServersSharedResults() {
        radar.polls.add(page(1, true, check("a.example.com", true), done(1, 0)));
        run(job(JobKind.CHECK_HOSTS, null, List.of("a.example.com"), false));
        assertEquals(List.of(JobRequest.ofHosts(List.of("a.example.com"), false)), radar.started);
        assertTrue(radar.calls.contains("start {\"hosts\":[\"a.example.com\"]}"), radar.calls.toString());
    }

    @Test
    void aRetriedCheckAgainStillSkipsTheSharedResults() {
        radar.starts.add(http(400, "{\"error\":\"bad\"}"));
        radar.polls.add(page(1, true, check("a.example.com", true), done(1, 0)));
        Job j = new Job(JobKind.CHECK_HOSTS, null, List.of("a.example.com"), false, false, true, x -> { });
        run(j);
        assertEquals(JobState.FAILED, j.state());
        assertTrue(j.resetForRetry());
        run(j);
        assertEquals(JobState.DONE, j.state());
        assertEquals(List.of("start {\"hosts\":[\"a.example.com\"],\"rescan\":true}",
                "start {\"hosts\":[\"a.example.com\"],\"rescan\":true}"),
                radar.calls.stream().filter(c -> c.startsWith("start ")).toList());
    }

    @Test
    void overlappingJobsSendEachHostOnce() {
        radar.polls.add(page(2, true, check("a.example.com", true), check("b.example.com", true), done(2, 0)));
        radar.polls.add(page(1, true, check("c.example.com", true), done(1, 0)));
        run(job(JobKind.CHECK_HOSTS, null, List.of("a.example.com", "b.example.com"), false));
        run(job(JobKind.CHECK_HOSTS, null, List.of("b.example.com", "c.example.com"), false));
        assertEquals(List.of(JobRequest.ofHosts(List.of("a.example.com", "b.example.com")),
                JobRequest.ofHosts(List.of("c.example.com"))), radar.started);
    }

    static final String REPEAT_DONE = "Done: 2 hosts, 0 with leaks. Only new subdomains and failed checks were sent."
            + " Tick Rescan to scan again.";

    @Test
    void aRepeatChecksOnlyNewAndFailedHosts() {
        checkedAgo("example.com", true, Duration.ofHours(1));
        checkedAgo("vpn.example.com", true, Duration.ofHours(1));
        checkedAgo("old.example.com", false, Duration.ofHours(1));
        store.found("example.com", List.of("blog.example.com"));
        radar.subdomains.add(subdomains("vpn.example.com", "blog.example.com", "new.example.com"));
        radar.polls.add(page(2, true, check("new.example.com", true), check("old.example.com", true), done(2, 0)));
        Job j = domainJob();
        run(j);
        assertTrue(radar.calls.contains("subdomains example.com false"), radar.calls.toString());
        assertEquals(List.of(JobRequest.ofHosts(List.of("new.example.com", "old.example.com"))), radar.started);
        assertEquals(REPEAT_DONE, j.status());
        assertTrue(statuses.stream().anyMatch(t -> t.startsWith("Checking 2 of 2")), statuses.toString());
        assertEquals(HostStatus.FOUND, store.host("blog.example.com").orElseThrow().status());
    }

    @Test
    void aRepeatListsNewSubdomainsEvenIfTheCheckFails() {
        checkedAgo("example.com", true, Duration.ofHours(1));
        radar.subdomains.add(subdomains("new.example.com"));
        radar.starts.add(http(401, "{\"error\":\"unauthorized\"}"));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.FAILED, j.state());
        assertEquals(HostStatus.FOUND, store.host("new.example.com").orElseThrow().status());
    }

    @Test
    void aRepeatWithNothingNewSendsNoCheck() {
        checkedAgo("example.com", true, Duration.ofHours(1));
        checkedAgo("vpn.example.com", true, Duration.ofHours(2));
        store.found("example.com", List.of("blog.example.com"));
        radar.subdomains.add(subdomains("vpn.example.com", "blog.example.com"));
        Job j = domainJob();
        assertEquals(List.of(), run(j));
        assertEquals(List.of(), radar.started);
        assertEquals(JobState.DONE, j.state());
        assertEquals(StatusText.nothingNew("example.com"), j.status());
        assertTrue(events.contains("Hirdman Radar: " + StatusText.nothingNew("example.com")), events.toString());
    }

    @Test
    void rescanScansTheDomainEvenWithFreshRows() {
        checkedAgo("example.com", true, Duration.ofHours(1));
        radar.polls.add(page(1, true, rootCheck("example.com"), done(0, 0)));
        run(job(JobKind.FIND_AND_CHECK, "example.com", List.of(), true));
        assertEquals(List.of(JobRequest.ofDomain("example.com", true)), radar.started);
        assertTrue(radar.calls.stream().noneMatch(t -> t.startsWith("subdomains")), radar.calls.toString());
    }

    @Test
    void alwaysRescanScansTheDomainEvenWithFreshRows() {
        checkedAgo("example.com", true, Duration.ofHours(1));
        options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, true, 5, true);
        radar.polls.add(page(1, true, rootCheck("example.com"), done(0, 0)));
        run(domainJob());
        assertEquals(List.of(JobRequest.ofDomain("example.com", true)), radar.started);
    }

    @Test
    void aDomainWithoutFreshRowsIsScanned() {
        checkedAgo("example.com", false, Duration.ofMinutes(1));
        store.found("example.com", List.of("blog.example.com"));
        radar.polls.add(page(1, true, rootCheck("example.com"), done(0, 0)));
        run(domainJob());
        assertEquals(List.of(JobRequest.ofDomain("example.com", false)), radar.started);
    }

    @Test
    void aDomainWithChecksOlderThanADayIsScanned() {
        // A full scan refreshes them in one job; hosts the server checked in the last day cost nothing.
        checkedAgo("example.com", true, Duration.ofHours(1));
        checkedAgo("vpn.example.com", true, Duration.ofHours(25));
        radar.polls.add(page(1, true, rootCheck("example.com"), done(0, 0)));
        run(domainJob());
        assertEquals(List.of(JobRequest.ofDomain("example.com", false)), radar.started);
    }

    static JobEvent limit() {
        return ev("subdomain_limit", "{\"count\":400,\"discovered\":403,"
                + "\"message\":\"Large perimeter: the most important subdomains were checked automatically\"}");
    }

    @Test
    void aFirstDomainCheckAfterAHostCheckScansTheDomain() {
        // A row from a host check is not a scan of the domain.
        checkedAgo("vpn.example.com", true, Duration.ofHours(1));
        radar.polls.add(page(1, true, rootCheck("example.com"), done(0, 0)));
        run(domainJob());
        assertEquals(List.of(JobRequest.ofDomain("example.com", false)), radar.started);
        assertTrue(radar.calls.stream().noneMatch(t -> t.startsWith("subdomains")), radar.calls.toString());
    }

    @Test
    void aRepeatWithMoreThanOneServerCheckScansTheDomainInstead() {
        // One scan instead of many host checks; the server reuses its saved host results.
        checkedAgo("example.com", true, Duration.ofHours(1));
        radar.subdomains.add(subdomains(IntStream.range(0, 51).mapToObj(i -> "h" + i + ".example.com").toArray(String[]::new)));
        radar.polls.add(page(1, true, rootCheck("example.com"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(List.of(JobRequest.ofDomain("example.com", false)), radar.started);
        assertEquals("Done: 1 host, 0 with leaks", j.status());
    }

    @Test
    void aScanCutByTheHourlyLimitSaysSoInsteadOfFailed() {
        // Without a key a scan spends the hourly host limit; the server leaves the rest unchecked and warns once.
        radar.polls.add(page(5, true, rootCheck("example.com"), check("vpn.example.com", false),
                ev("service_warning", "{\"service\":\"hourly_limit\",\"message\":\"Hourly host limit without a key reached\"}"),
                check("mail.example.com", false), done(3, 2)));
        Job j = domainJob();
        run(j);
        assertEquals("Done: 3 hosts, 0 with leaks, 2 not checked yet. Hourly limit reached: the rest are listed as Not checked yet.",
                j.status());
        assertEquals(HostStatus.NOT_CHECKED, store.host("vpn.example.com").orElseThrow().status());
    }

    @Test
    void otherServiceWarningsChangeNothing() {
        radar.polls.add(page(3, true, rootCheck("example.com"),
                ev("service_warning", "{\"service\":\"crtsh\",\"message\":\"crt.sh did not answer\"}"), done(1, 0)));
        Job j = domainJob();
        run(j);
        assertEquals("Done: 1 host, 0 with leaks", j.status());
    }

    @Test
    void aLargePerimeterListsTheRestAsNotCheckedYet() {
        radar.polls.add(page(4, true, rootCheck("example.com"), check("vpn.example.com", true), limit(), done(1, 0)));
        radar.subdomains.add(subdomains("vpn.example.com", "rest1.example.com", "rest2.example.com"));
        Job j = domainJob();
        run(j);
        assertEquals("Done: 2 hosts, 0 with leaks. Large perimeter: the 400 most important of 403 subdomains were checked;"
                + " the rest are listed as Not checked yet.", j.status());
        assertTrue(events.contains("Hirdman Radar: large perimeter of example.com: the 400 most important of 403 subdomains"
                + " were checked; the rest are listed as Not checked yet."), events.toString());
        assertEquals(HostStatus.FOUND, store.host("rest1.example.com").orElseThrow().status());

        // A repeat leaves the rest for the user to select.
        radar.subdomains.add(subdomains("vpn.example.com", "rest1.example.com", "rest2.example.com"));
        Job again = domainJob();
        run(again);
        assertEquals(1, radar.started.size());
        assertEquals(StatusText.nothingNew("example.com"), again.status());
    }

    @Test
    void aSavedLargeScanKeepsOneFullStopBetweenTheTails() {
        JobEvent cached = ev("scan_started", "{\"cached\":\"true\",\"domain\":\"example.com\",\"mode\":\"basic\",\"scan_id\":\"x\"}");
        radar.polls.add(page(4, true, cached, rootCheck("example.com"), limit(), done(0, 0)));
        radar.subdomains.add(subdomains("rest1.example.com"));
        Job j = job(JobKind.FIND_AND_CHECK, "example.com", List.of(), true);
        run(j);
        assertEquals("Done: 1 host, 0 with leaks" + SAVED + " Large perimeter: the 400 most important of 403 subdomains were"
                + " checked; the rest are listed as Not checked yet.", j.status());
    }

    @Test
    void aFailedListOfTheRestDoesNotFailTheScan() {
        radar.polls.add(page(3, true, rootCheck("example.com"), limit(), done(0, 0)));
        radar.subdomains.add(http(503, ""));
        Job j = domainJob();
        run(j);
        assertEquals("Done: 1 host, 0 with leaks. Large perimeter: the 400 most important of 403 subdomains were checked.",
                j.status());
        assertEquals(1, radar.calls.stream().filter(t -> t.startsWith("subdomains")).count(), radar.calls.toString());
        assertTrue(events.stream().anyMatch(e -> e.startsWith("Hirdman Radar: subdomains of example.com left unchecked by the scan could not be listed")),
                events.toString());
    }

    static final String OFF_MID_JOB = "Failed: Private project was ticked, so nothing more was sent.";

    @Test
    void privateProjectTickedMidJobSendsNothingMore() {
        radar.polls.add(page(3, false, started()));
        radar.polls.add(page(4, true, done(0, 0)));
        // The pause between polls is where the user ticks the switch.
        JobRunner r = runner(() -> radar, (d, job) -> options = new JobRunner.RunOptions(
                URI.create("https://scan.hirdman.pro"), null, false, 5, true, true), () -> options);
        Job j = domainJob();
        r.run(j, j.token());
        assertEquals(JobState.FAILED, j.state());
        assertEquals(OFF_MID_JOB, j.status());
        assertEquals(List.of("meta", "start {\"domain\":\"example.com\",\"rescan\":false}", "poll j1 0"), radar.calls);
    }

    @Test
    void privateProjectTickedDuringTheLastPageListsNothingMore() {
        radar.polls.add(page(4, true, rootCheck("example.com"), limit(), done(0, 0)));
        store.addCheckListener(r -> options = new JobRunner.RunOptions(URI.create("https://scan.hirdman.pro"), null, false,
                5, true, true));
        Job j = domainJob();
        run(j);
        assertEquals(OFF_MID_JOB, j.status());
        assertTrue(radar.calls.stream().noneMatch(t -> t.startsWith("subdomains")), radar.calls.toString());
    }

    @Test
    void rateLimitWaitsStartAfreshAfterProgress() {
        // A long host check waits for the hourly limit again and again; only waiting without progress ends it.
        String hourly = "{\"error\":\"hourly limit without a key: 300 hosts per hour\"}";
        List<String> all = hosts(0, 150);
        radar.starts.add("j1");
        radar.starts.add(http(429, hourly, "Retry-After", "3600"));
        radar.starts.add("j2");
        radar.starts.add(http(429, hourly, "Retry-After", "3600"));
        radar.starts.add("j3");
        radar.polls.add(page(51, true, plus(checks(all.subList(0, 50)), done(50, 0))));
        radar.polls.add(page(51, true, plus(checks(all.subList(50, 100)), done(50, 0))));
        radar.polls.add(page(51, true, plus(checks(all.subList(100, 150)), done(50, 0))));
        Job j = job(JobKind.CHECK_HOSTS, null, all, false);
        run(j);
        assertEquals(JobState.DONE, j.state(), j.status());
        assertEquals(List.of(Duration.ofHours(1), Duration.ofHours(1)), pauses.stream().filter(d -> d.toMinutes() >= 60).toList());
        assertEquals(150, store.all().size());
    }

    static final String FOREIGN = "Hirdman Radar: the server answered for hosts this job did not ask about; they were ignored (";

    @Test
    void checksOfHostsAHostJobDidNotSendAreDropped() {
        radar.polls.add(page(3, true, check("a.example.com", true), check("login.microsoftonline.com", true, "high"),
                check("b.example.com", true, "high"), done(1, 0)));
        Job j = job(JobKind.CHECK_HOSTS, null, List.of("a.example.com"), false);
        run(j);
        assertEquals(List.of("a.example.com"), store.all().stream().map(HostResult::host).toList());
        assertEquals(List.of(FOREIGN + "login.microsoftonline.com)"), errors);
        assertEquals("Done: 1 host, 0 with leaks", j.status());
    }

    @Test
    void aDomainJobKeepsOnlyTheDomainAndItsSubdomains() {
        radar.polls.add(page(5, true, rootCheck("example.com"), check("vpn.example.com", true), check("evil.org", true, "high"),
                check("notexample.com", true, "high"), limit(), done(1, 0)));
        radar.subdomains.add(subdomains("rest.example.com", "other.org", "Deep.Rest.Example.com"));
        run(domainJob());
        assertEquals(List.of("deep.rest.example.com", "example.com", "rest.example.com", "vpn.example.com"),
                store.all().stream().map(HostResult::host).sorted().toList());
        assertEquals(List.of(FOREIGN + "evil.org)"), errors);
    }

    @Test
    void subdomainListsKeepOnlyNamesUnderTheDomain() {
        radar.subdomains.add(subdomains("a.example.com", "evil.org", "example.com.evil.org"));
        run(job(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false));
        assertEquals(List.of("a.example.com"), store.all().stream().map(HostResult::host).toList());

        // The repeat path sends only new names under the domain.
        checkedAgo("example.com", true, Duration.ofHours(1));
        checkedAgo("a.example.com", true, Duration.ofHours(1));
        radar.subdomains.add(subdomains("a.example.com", "new.example.com", "other.org"));
        radar.polls.add(page(1, true, check("new.example.com", true), done(1, 0)));
        run(domainJob());
        assertEquals(List.of(JobRequest.ofHosts(List.of("new.example.com"))), radar.started);
    }

    // Polls of a live server job.

    @Test
    void aPollWaitsAtMostFortyFiveSeconds() {
        radar.polls.add(page(3, false, started()));
        radar.polls.add(http(503, "", "Retry-After", "900"));
        radar.polls.add(page(4, true, rootCheck("example.com"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(List.of(JobRunner.POLL_PAUSE, Duration.ofSeconds(45)), pauses);
        assertEquals(JobState.DONE, j.state(), j.status());
    }

    static ApiException malformed() {
        return ApiException.malformed("answer is not a JSON object", null);
    }

    @Test
    void aMalformedPollIsPolledAgainWithTheSameCursor() {
        radar.polls.add(page(3, false, started()));
        radar.polls.add(malformed());
        radar.polls.add(page(4, true, rootCheck("example.com"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(List.of(0, 3, 3), radar.pollAfters);
        assertEquals(JobState.DONE, j.state(), j.status());
        assertTrue(statuses.contains("Unexpected answer from the server. Retrying in 2 s, attempt 1 of 3."), statuses.toString());
    }

    @Test
    void threeMalformedPollsFailAndFreeTheServerSlot() {
        for (int i = 0; i < 3; i++) {
            radar.polls.add(malformed());
        }
        Job j = domainJob();
        run(j);
        assertEquals(3, radar.pollAfters.size());
        assertEquals("Failed: Unexpected answer from the server", j.status());
        assertEquals(List.of("j1"), radar.deleted);
    }

    @Test
    void aMalformedStartStillFailsAtOnce() {
        radar.starts.add(malformed());
        Job j = domainJob();
        run(j);
        assertEquals("Failed: Unexpected answer from the server", j.status());
        assertEquals(1, radar.started.size());
        assertEquals(List.of(), radar.deleted);
    }

    @Test
    void aFailedPollDeletesTheServerJob() {
        for (int i = 0; i < 5; i++) {
            radar.polls.add(unreachable());
        }
        Job j = domainJob();
        run(j);
        assertEquals(List.of("j1"), radar.deleted);
        assertEquals(null, j.token().serverJob());
    }

    @Test
    void aJobTheServerEndedIsNotDeleted() {
        radar.polls.add(page(3, true, check("x.example.com", false), error("scan cancelled"), done(1, 1)));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.FAILED, j.state());
        assertEquals(List.of(), radar.deleted);
        assertEquals(null, j.token().serverJob());
    }

    @Test
    void aPrivateProjectDeletesNothingOnFailure() {
        radar.polls.add(page(3, false, started()));
        JobRunner r = runner(() -> radar, (d, job) -> options = new JobRunner.RunOptions(
                URI.create("https://scan.hirdman.pro"), null, false, 5, true, true), () -> options);
        Job j = domainJob();
        r.run(j, j.token());
        assertEquals(OFF_MID_JOB, j.status());
        assertEquals(List.of(), radar.deleted);
    }

    // The client comes from the same settings snapshot as the run.

    @Test
    void theClientIsMadeForTheServerOfTheRun() {
        List<URI> asked = new CopyOnWriteArrayList<>();
        radar.polls.add(page(2, true, rootCheck("example.com"), done(0, 0)));
        JobRunner r = new JobRunner(server -> {
            asked.add(server);
            return radar;
        }, store, gate, (d, job) -> { }, () -> options, events::add, errors::add, () -> 0.5, clock::get, Runnable::run);
        Job j = domainJob();
        r.run(j, j.token());
        assertEquals(List.of(URI.create("https://scan.hirdman.pro")), asked);
        assertEquals(JobState.DONE, j.state());
    }

    @Test
    void theServerJobIsKeptWithItsClientWhileItRuns() {
        java.util.concurrent.atomic.AtomicReference<CancelToken.ServerJob> live = new java.util.concurrent.atomic.AtomicReference<>();
        Job j = domainJob();
        radar.polls.add(page(1, false, started()));
        radar.polls.add(page(2, true, rootCheck("example.com"), done(0, 0)));
        runner(() -> radar, (d, job) -> live.set(j.token().serverJob()), () -> options).run(j, j.token());
        assertEquals(new CancelToken.ServerJob(radar, "j1"), live.get());
        assertEquals(null, j.token().serverJob(), "an ended server job needs no delete");
    }

    @Test
    void noClientForTheServerFailsInsteadOfThrowing() {
        Job j = domainJob();
        runner(() -> null).run(j, j.token());
        assertEquals("Failed: Server URL in Settings > Extensions > Hirdman Radar is not valid.", j.status());
        assertTrue(errors.isEmpty(), errors.toString());
    }

    // Limits against a server that floods the project.

    @Test
    void aDomainJobTakesAtMostAThousandRows() {
        List<String> many = hosts(0, JobRunner.MAX_ROWS + 1);
        radar.polls.add(page(2000, false, checks(many)));
        Job j = domainJob();
        run(j);
        assertEquals("Failed: Unexpected answer from the server", j.status());
        assertEquals(JobRunner.MAX_ROWS, store.all().size());
        assertEquals(List.of("j1"), radar.deleted);
        assertTrue(errors.contains("Hirdman Radar: example.com: the server sent checks of more than 1000 hosts"), errors.toString());
    }

    @Test
    void aHostJobMayHaveMoreRowsThanTheLimitIfItAskedForThem() {
        List<String> many = hosts(0, JobRunner.MAX_ROWS + 50);
        radar.metas.add(new Meta(1, null, "key", new Meta.Limits(400, 3, 0), null));
        for (int i = 0; i < many.size(); i += 400) {
            List<String> part = many.subList(i, Math.min(i + 400, many.size()));
            radar.polls.add(page(part.size() + 1, true, plus(checks(part), done(part.size(), 0))));
        }
        Job j = job(JobKind.CHECK_HOSTS, null, many, false);
        run(j);
        assertEquals(JobState.DONE, j.state(), j.status());
        assertEquals(many.size(), store.all().size());
    }

    @Test
    void aServerJobEndsAfterTwoHours() {
        // Each pause moves the clock; a server that never says done is stopped.
        JobRunner r = runner(() -> radar, (d, job) -> clock.addAndGet(Duration.ofMinutes(30).toNanos()), () -> options);
        for (int i = 0; i < 10; i++) {
            radar.polls.add(page(i + 1, false, ev("progress", "{\"checked\":1,\"total\":2}")));
        }
        Job j = domainJob();
        r.run(j, j.token());
        assertEquals("Failed: Unexpected answer from the server", j.status());
        assertEquals(5, radar.pollAfters.size());
        assertTrue(errors.contains("Hirdman Radar: example.com: the server job ran over 2 hours"), errors.toString());
    }

    @Test
    void tooManyEmptyPagesInARowEndTheJob() {
        for (int i = 0; i < JobRunner.MAX_EMPTY_PAGES; i++) {
            radar.polls.add(page(0, false));
        }
        Job j = domainJob();
        run(j);
        assertEquals("Failed: Unexpected answer from the server", j.status());
        assertEquals(JobRunner.MAX_EMPTY_PAGES, radar.pollAfters.size());
    }

    @Test
    void anEventResetsTheEmptyPageCount() {
        for (int i = 0; i < JobRunner.MAX_EMPTY_PAGES - 1; i++) {
            radar.polls.add(page(0, false));
        }
        radar.polls.add(page(1, false, started()));
        for (int i = 0; i < JobRunner.MAX_EMPTY_PAGES - 1; i++) {
            radar.polls.add(page(1, false));
        }
        radar.polls.add(page(2, true, rootCheck("example.com"), done(0, 0)));
        Job j = domainJob();
        run(j);
        assertEquals(JobState.DONE, j.state(), j.status());
    }

    // A cancel does not wait for the answer of the request in flight.

    @Test
    void aCancelEndsTheWaitForAHangingPoll() throws Exception {
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        radar.polls.add(new FakeRadar.Hang(release, page(1, true, rootCheck("example.com"), done(0, 0))));
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newCachedThreadPool();
        JobRunner r = new JobRunner(server -> radar, store, gate, (d, job) -> { }, () -> options, events::add, errors::add,
                () -> 0.5, clock::get, pool);
        Job j = domainJob();
        Thread worker = new Thread(() -> r.run(j, j.token()));
        worker.start();
        JobQueueTest.waitUntil(() -> radar.calls.contains("poll j1 0"));
        long t = System.nanoTime();
        j.markCancelled(false);
        worker.join(5000);
        assertTrue(System.nanoTime() - t < Duration.ofSeconds(1).toNanos());
        JobQueueTest.waitUntil(() -> radar.calls.contains("interrupted"));
        release.countDown();
        r.close();
        assertTrue(store.all().isEmpty());
    }

    @Test
    void aStartLeftBehindByACancelIsDeletedWhenItsIdComes() throws Exception {
        java.util.concurrent.CountDownLatch inStart = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch answer = new java.util.concurrent.CountDownLatch(1);
        Radar slowStart = new Radar() {
            @Override
            public Meta meta() throws ApiException {
                return radar.meta();
            }

            @Override
            public SubdomainList subdomains(String domain, boolean rescan) throws ApiException {
                return radar.subdomains(domain, rescan);
            }

            @Override
            public String startJob(JobRequest request) {
                inStart.countDown();
                // Burp's client does not stop on an interrupt: the answer still comes.
                while (true) {
                    try {
                        answer.await();
                        return "j9";
                    } catch (InterruptedException e) {
                        // Keep waiting, as a request that ignores interrupts does.
                    }
                }
            }

            @Override
            public JobPage poll(String jobId, int after) throws ApiException {
                return radar.poll(jobId, after);
            }

            @Override
            public void deleteJob(String jobId, Duration timeout) {
                radar.deleteJob(jobId, timeout);
            }
        };
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newCachedThreadPool();
        JobRunner r = new JobRunner(server -> slowStart, store, gate, (d, job) -> { }, () -> options, events::add,
                errors::add, () -> 0.5, clock::get, pool);
        Job j = domainJob();
        Thread worker = new Thread(() -> r.run(j, j.token()));
        worker.start();
        assertTrue(inStart.await(5, java.util.concurrent.TimeUnit.SECONDS));
        j.markCancelled(false);
        worker.join(5000);
        assertTrue(!worker.isAlive());
        assertEquals(List.of(), radar.deleted);
        answer.countDown();
        JobQueueTest.waitUntil(() -> radar.deleted.contains("j9"));
        r.close();
    }
}
