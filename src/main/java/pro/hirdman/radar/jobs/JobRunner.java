package pro.hirdman.radar.jobs;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.stream.Stream;
import pro.hirdman.radar.Threads;
import pro.hirdman.radar.Version;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.ConnectionSettings;
import pro.hirdman.radar.api.JobEvent;
import pro.hirdman.radar.api.JobPage;
import pro.hirdman.radar.api.JobRequest;
import pro.hirdman.radar.api.Json;
import pro.hirdman.radar.api.MalformedEventException;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.ServerEvent;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.SubdomainList;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.model.HostNames;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.ResultStore;

/** Runs one job against the radar server: retries, server queue, polling, and one resume after a lost server job. */
public final class JobRunner {

    /** {@code serverProblem} is set (and {@code server} may be null) when the Server URL setting is invalid. */
    public record RunOptions(URI server, String serverProblem, boolean alwaysRescan, int maxAttempts,
            boolean recheckNotChecked, boolean offForProject) {

        public RunOptions(URI server, String serverProblem, boolean alwaysRescan, int maxAttempts, boolean recheckNotChecked) {
            this(server, serverProblem, alwaysRescan, maxAttempts, recheckNotChecked, false);
        }

        public static RunOptions of(Options o) {
            Optional<String> problem = o.serverUrlProblem();
            URI server = problem.isPresent() ? null : ConnectionSettings.of(o.serverUrl()).server();
            return new RunOptions(server, problem.orElse(null), o.alwaysRescan(), o.attempts(), o.recheckNotChecked(),
                    o.offForProject());
        }
    }

    public static final String OFF_FOR_PROJECT = "Private project: nothing was sent. The switch is at the bottom of the Hirdman Radar tab.";
    static final String OFF_MID_JOB = "Private project was ticked, so nothing more was sent.";
    private static final String BAD_SERVER = "Server URL in Settings > Extensions > Hirdman Radar is not valid.";
    static final String CRASHED = "Unexpected error. Details are in the extension's Errors tab.";

    private static final String FAILED = " failed: ";

    static final Duration POLL_PAUSE = Duration.ofSeconds(2);
    /** Malformed events written to the Errors tab per job; the rest are counted, not logged. */
    static final int MALFORMED_LOGGED = 3;
    static final String FOREIGN = "Hirdman Radar: the server answered for hosts this job did not ask about; they were ignored (";
    static final Duration RECHECK_DELAY = Duration.ofMinutes(2);
    private static final Duration DELETE_TIMEOUT = Duration.ofSeconds(10);
    /** A failed run frees its server slot with a short best-effort delete. */
    private static final Duration FAIL_DELETE_TIMEOUT = Duration.ofSeconds(5);
    /** How often a worker waiting for an answer looks at the cancel flag. */
    private static final Duration CANCEL_CHECK = Duration.ofMillis(100);
    static final String UNEXPECTED = RetryPolicy.MALFORMED;
    /** Limits against a server that floods the project: rows per job, the life of a server job, silent pages. */
    static final int MAX_ROWS = 1000;
    static final Duration MAX_SERVER_JOB = Duration.ofHours(2);
    static final int MAX_EMPTY_PAGES = 200;

    private final Function<URI, Radar> radar;
    private final ResultStore store;
    private final MetaGate gate;
    private final Sleeper sleeper;
    private final Supplier<RunOptions> options;
    private final Consumer<String> events;
    private final Consumer<String> errors;
    private final DoubleSupplier random;
    private final LongSupplier nanoTime;
    /** Requests run here, so a cancel does not wait for an answer. */
    private final Executor calls;

    /** {@code radar} makes the client for the server of the run's settings snapshot. */
    public JobRunner(Function<URI, Radar> radar, ResultStore store, MetaGate gate, Sleeper sleeper,
            Supplier<RunOptions> options, Consumer<String> events, Consumer<String> errors) {
        this(radar, store, gate, sleeper, options, events, errors, () -> ThreadLocalRandom.current().nextDouble(),
                System::nanoTime, Executors.newCachedThreadPool(Threads.daemon("hirdman-radar-http")));
    }

    /** One client whatever the server; for callers that never send anything. */
    public JobRunner(Supplier<Radar> radar, ResultStore store, MetaGate gate, Sleeper sleeper,
            Supplier<RunOptions> options, Consumer<String> events, Consumer<String> errors) {
        this(server -> radar.get(), store, gate, sleeper, options, events, errors);
    }

    JobRunner(Function<URI, Radar> radar, ResultStore store, MetaGate gate, Sleeper sleeper, Supplier<RunOptions> options,
            Consumer<String> events, Consumer<String> errors, DoubleSupplier random, LongSupplier nanoTime, Executor calls) {
        this.radar = radar;
        this.store = store;
        this.gate = gate;
        this.sleeper = sleeper;
        this.options = options;
        this.events = events;
        this.errors = errors;
        this.random = random;
        this.nanoTime = nanoTime;
        this.calls = calls;
    }

    /** Extension unload: requests still waiting for an answer are interrupted. */
    void close() {
        if (calls instanceof ExecutorService service) {
            service.shutdownNow();
        }
    }

    /** Event log line for a job just put in the queue. */
    void queued(Job job) {
        events.accept("Hirdman Radar: queued " + what(job));
    }

    /** Event log line for a request that matched a job already waiting or running. */
    void alreadyQueued(Job job) {
        events.accept("Hirdman Radar: " + what(job) + " is already in the queue");
    }

    private static String what(Job job) {
        if (job.domain() == null) {
            return subject(job);
        }
        return (job.kind() == JobKind.FIND_SUBDOMAINS ? "subdomain search for " : "leak check for ") + job.domain();
    }

    /** How event log lines name a job: its domain, or what it checks. */
    private static String subject(Job job) {
        if (job.domain() != null) {
            return job.domain();
        }
        String hosts = StatusText.hosts(job.hosts().size());
        if (job.recheck()) {
            return "re-check of " + hosts;
        }
        if (job.force()) {
            return "check again of " + hosts;
        }
        return "leak check of " + hosts;
    }

    /** Unwinds a run that has ended: the job is already failed or cancelled. */
    private static final class Stop extends Exception {
        private static final long serialVersionUID = 1L;

        Stop() {
            super(null, null, false, false);
        }
    }

    private sealed interface Outcome permits Finished, Errored, Lost {
    }

    private record Finished() implements Outcome {
    }

    private record Errored(String message) implements Outcome {
    }

    private record Lost() implements Outcome {
    }

    @FunctionalInterface
    private interface ApiCall<T> {
        T call(Radar r) throws ApiException;
    }

    /** State of one run. */
    private static final class Run {
        final Job job;
        final CancelToken token;
        RunOptions o;
        Radar radar;
        Meta meta;
        int attempts;
        Duration waitedOn429 = Duration.ZERO;
        String runningStatus;
        String lastError;
        boolean savedScan;
        /** Set when the server stopped checking at the hourly host limit. */
        boolean hourlyCut;
        /** Set when the domain scan left less important subdomains unchecked. */
        ServerEvent.SubdomainLimit limit;
        /** Hosts this run sends itself; null while the server scans the whole domain. */
        List<String> toCheck;
        /** Every host a host job sent; checks of other hosts are dropped. */
        final Set<String> sent = new HashSet<>();
        boolean foreignLogged;
        int malformed;
        /** Hosts left out as checked in the last 24 h. */
        int skipped;
        /** Rows written by this run, by host. */
        final Map<String, HostResult> rows = new LinkedHashMap<>();

        Run(Job job, CancelToken token, RunOptions o) {
            this.job = job;
            this.token = token;
            this.o = o;
        }
    }

    /** Runs the job to its end; returns the hosts to check again later, empty when there are none. */
    public List<String> run(Job job, CancelToken token) {
        Run c = new Run(job, token, null);
        try {
            c.o = options.get();
            if (c.o.offForProject()) {
                throw fail(c, OFF_FOR_PROJECT);
            }
            if (c.o.server() == null || c.o.serverProblem() != null) {
                throw fail(c, BAD_SERVER
                        + (c.o.serverProblem() == null ? "" : " " + c.o.serverProblem()));
            }
            c.radar = radar.apply(c.o.server());
            if (c.radar == null) {
                throw fail(c, BAD_SERVER);
            }
            if (job.kind() == JobKind.CHECK_HOSTS) {
                c.toCheck = job.force() ? job.hosts() : toSend(job.hosts());
                c.skipped = job.hosts().size() - c.toCheck.size();
                if (c.toCheck.isEmpty() && c.skipped > 0) {
                    // Nothing goes out, not even /meta.
                    String status = StatusText.allFresh(c.skipped);
                    job.update(JobState.DONE, status);
                    event(c, "Hirdman Radar: finished " + subject(job) + ". " + status);
                    return List.of();
                }
                c.runningStatus = StatusText.checking(0, c.toCheck.size(), 0);
            } else {
                c.runningStatus = StatusText.finding();
            }
            running(c);
            c.meta = meta(c);
            switch (job.kind()) {
                case FIND_SUBDOMAINS -> findSubdomains(c);
                case FIND_AND_CHECK -> checkDomain(c);
                case CHECK_HOSTS -> checkHosts(c);
            }
            return recheckList(c);
        } catch (Stop s) {
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return List.of();
        } catch (RuntimeException e) {
            crashed(c, e);
            return List.of();
        }
    }

    /** A run that threw: the trace goes to the Errors tab and the job fails. */
    void crashed(Job job, Throwable t) {
        crashed(new Run(job, job.token(), null), t);
    }

    private void crashed(Run c, Throwable t) {
        StringWriter trace = new StringWriter();
        t.printStackTrace(new PrintWriter(trace));
        error(c, "Hirdman Radar: unexpected error in " + subject(c.job) + ": " + trace);
        fail(c, CRASHED);
    }

    private Meta meta(Run c) throws Stop, InterruptedException {
        if (gate.needsCheck(c.o.server())) {
            Meta m = call(c, Radar::meta);
            gate.passed(c.o.server(), m);
            String need = m.minPluginVersion();
            if (need != null && !Version.atLeast(Version.current(), need)) {
                error(c, "Hirdman Radar: this plugin is older than the server expects (" + Json.oneLine(need) + ")");
            }
        }
        return gate.last().orElseThrow();
    }

    private void findSubdomains(Run c) throws Stop, InterruptedException {
        String domain = validDomain(c);
        boolean rescan = c.job.rescan() || c.o.alwaysRescan();
        SubdomainList list = call(c, r -> r.subdomains(domain, rescan));
        checkCancelled(c);
        List<String> hosts = under(domain, list);
        store.found(domain, hosts);
        c.job.update(JobState.DONE, StatusText.doneFound(hosts.size()));
        event(c, "Hirdman Radar: finished " + subject(c.job) + ", " + StatusText.hosts(hosts.size()));
    }

    private void checkDomain(Run c) throws Stop, InterruptedException {
        String domain = validDomain(c);
        boolean rescan = c.job.rescan() || c.o.alwaysRescan();
        if (!rescan && repeat(domain) && checkNewHosts(c, domain)) {
            return;
        }
        scanDomain(c, domain, rescan);
    }

    /** Without a key a scan spends the hourly host limit on hosts the server checks anew; saved results are free. */
    private void scanDomain(Run c, String domain, boolean rescan) throws Stop, InterruptedException {
        runResumable(c, JobRequest.ofDomain(domain, rescan), null);
        String tail = "";
        if (c.limit != null) {
            checkCancelled(c);
            checkPrivate(c);
            String text = StatusText.largePerimeter(c.limit.count(), c.limit.discovered(), listRest(c, domain));
            event(c, "Hirdman Radar: large perimeter of " + domain + ": " + text);
            tail = ". Large perimeter: " + text;
        }
        finish(c, rescan && c.savedScan, tail);
    }

    /** Lists the subdomains a large scan left unchecked as "Not checked yet"; one try, a failure only logs. */
    private boolean listRest(Run c, String domain) throws Stop, InterruptedException {
        try {
            store.found(domain, under(domain, send(c, r -> r.subdomains(domain, false), null)));
            return true;
        } catch (ApiException e) {
            event(c, "Hirdman Radar: subdomains of " + domain + " left unchecked by the scan could not be listed: "
                    + e.getMessage());
            return false;
        }
    }

    /**
     * A repeat: the domain itself (the row a scan writes) was checked in the last 24 h and no row of it longer ago.
     * Older checks are refreshed by a scan, which reuses the server's saved host results for free.
     */
    private boolean repeat(String domain) {
        Instant now = Instant.now();
        return store.host(domain).filter(r -> r.freshAt(now)).isPresent()
                && store.domain(domain).stream().filter(HostResult::checked).allMatch(r -> r.freshAt(now));
    }

    /**
     * Sends only new subdomains and failed checks; "Not checked yet" rows wait to be selected. False when they need
     * more than one server check: a scan costs no hosts of the hourly limit.
     */
    private boolean checkNewHosts(Run c, String domain) throws Stop, InterruptedException {
        List<String> subdomains = domainHosts(c, domain);
        checkCancelled(c);
        List<String> failed = store.domain(domain).stream()
                .filter(r -> r.status() == HostStatus.NOT_CHECKED).map(HostResult::host).toList();
        List<String> send = Stream.concat(subdomains.stream().filter(h -> store.host(h).isEmpty()), failed.stream())
                .distinct().toList();
        // Listed before the check, so a failed check still leaves the new names in the table.
        store.found(domain, subdomains);
        if (send.size() > c.meta.limits().maxHosts()) {
            return false;
        }
        if (send.isEmpty()) {
            String status = StatusText.nothingNew(domain);
            c.job.update(JobState.DONE, status);
            event(c, "Hirdman Radar: " + status);
            return true;
        }
        sendHosts(c, send);
        finish(c, false, StatusText.REPEAT);
        return true;
    }

    /** The hosts a plain check sends: those without a successful check in the last 24 h, in order. */
    List<String> toSend(List<String> hosts) {
        Instant now = Instant.now();
        return hosts.stream().filter(h -> store.host(h).filter(r -> r.freshAt(now)).isEmpty()).toList();
    }

    private void checkHosts(Run c) throws Stop, InterruptedException {
        sendHosts(c, c.toCheck);
        finish(c, false, StatusText.skipped(c.skipped));
    }

    /** Host checks in batches of max_hosts; progress counts these hosts. */
    private void sendHosts(Run c, List<String> hosts) throws Stop, InterruptedException {
        c.toCheck = hosts;
        hosts.stream().map(HostNames::normalize).flatMap(Optional::stream).forEach(c.sent::add);
        c.runningStatus = StatusText.checking(0, hosts.size(), c.meta.limits().hostsPerSec());
        running(c);
        // Check again is the user's own call, so it skips the server's shared results too.
        for (List<String> batch : batches(c, hosts)) {
            runResumable(c, JobRequest.ofHosts(batch, c.job.force()), batch);
        }
    }

    /**
     * One server job, resumed once if the server loses it: the hosts without a Check go out again as host checks.
     * {@code batch} is null for a domain job, whose hosts come from /subdomains.
     */
    private void runResumable(Run c, JobRequest request, List<String> batch) throws Stop, InterruptedException {
        Outcome out = serverJob(c, request);
        if (out instanceof Errored e) {
            throw fail(c, e.message());
        }
        if (out instanceof Finished) {
            return;
        }
        List<String> left = (batch != null ? batch : domainHosts(c, request.domain())).stream()
                .filter(h -> !c.rows.containsKey(h)).toList();
        if (left.isEmpty()) {
            return;
        }
        event(c, "Hirdman Radar: " + subject(c.job) + " was interrupted on the server, resuming");
        for (List<String> part : batches(c, left)) {
            Outcome again = serverJob(c, JobRequest.ofHosts(part, c.job.force()));
            if (again instanceof Lost) {
                throw fail(c, c.lastError != null ? c.lastError : "The server stopped the job");
            }
            if (again instanceof Errored e) {
                throw fail(c, e.message());
            }
        }
    }

    /** The domain and its subdomains as the server's last scan found them. */
    private List<String> domainHosts(Run c, String domain) throws Stop, InterruptedException {
        SubdomainList list = call(c, r -> r.subdomains(domain, false));
        return Stream.concat(Stream.of(domain), under(domain, list).stream()).distinct().toList();
    }

    /** Normalized names under {@code domain}: a server list cannot put rows on other hosts. */
    private static List<String> under(String domain, SubdomainList list) {
        return list.subdomains().stream().map(SubdomainList.Subdomain::host).map(HostNames::normalize)
                .flatMap(Optional::stream).filter(h -> HostNames.within(h, domain)).distinct().toList();
    }

    /** Server jobs take at most limits.max_hosts hosts. */
    private static List<List<String>> batches(Run c, List<String> hosts) {
        int size = Math.max(1, c.meta.limits().maxHosts());
        List<List<String>> out = new ArrayList<>();
        for (int i = 0; i < hosts.size(); i += size) {
            out.add(hosts.subList(i, Math.min(i + size, hosts.size())));
        }
        return out;
    }

    private Outcome serverJob(Run c, JobRequest request) throws Stop, InterruptedException {
        Radar server = c.radar;
        // A start abandoned by a cancel may still create the job: it is deleted when its id comes.
        String id = call(c, r -> r.startJob(request), false, late -> deleteLater(server, late, DELETE_TIMEOUT));
        c.token.serverJob(new CancelToken.ServerJob(server, id));
        if (c.token.cancelled()) {
            // Cancelled while the job was being created, so the queue may have missed its id.
            deleteQuietly(server, id, DELETE_TIMEOUT);
            throw new Stop();
        }
        long started = nanoTime.getAsLong();
        int after = 0;
        int emptyPages = 0;
        String runError = null;
        boolean sawDone = false;
        while (true) {
            JobPage page = poll(c, id, after);
            if (page == null) {
                c.token.serverJob(null);
                return new Lost();
            }
            for (JobEvent e : page.events()) {
                checkCancelled(c);
                Optional<ServerEvent> parsed = parse(c, e);
                if (parsed.isEmpty()) {
                    continue;
                }
                switch (parsed.get()) {
                    case ServerEvent.ScanStarted s -> {
                        c.savedScan |= s.cached();
                        if (c.toCheck == null) {
                            c.runningStatus = StatusText.finding();
                        }
                    }
                    case ServerEvent.Queued q -> c.runningStatus = StatusText.serverQueue(q.position(), q.etaSec());
                    case ServerEvent.Progress p -> {
                        if (c.toCheck == null) {
                            c.runningStatus = StatusText.checking(p.checked(), p.total(), c.meta.limits().hostsPerSec());
                        }
                    }
                    case Check check -> accept(c, check);
                    case ServerEvent.ErrorEvent err -> {
                        runError = err.message();
                        c.lastError = err.message();
                    }
                    case ServerEvent.SubdomainLimit l -> c.limit = l;
                    case ServerEvent.ServiceWarning w -> c.hourlyCut |= w.hourlyLimit();
                    case ServerEvent.Done d -> sawDone = true;
                }
            }
            if (c.toCheck != null) {
                c.runningStatus = StatusText.checking(c.rows.size(), c.toCheck.size(), c.meta.limits().hostsPerSec());
            }
            running(c);
            after = Math.max(after, page.next());
            if (page.done()) {
                c.token.serverJob(null);
                if (!sawDone) {
                    return new Lost();
                }
                return runError != null ? new Errored(runError) : new Finished();
            }
            emptyPages = page.events().isEmpty() ? emptyPages + 1 : 0;
            if (emptyPages >= MAX_EMPTY_PAGES) {
                throw unexpected(c, "the server sent " + MAX_EMPTY_PAGES + " empty pages in a row");
            }
            if (nanoTime.getAsLong() - started > MAX_SERVER_JOB.toNanos()) {
                throw unexpected(c, "the server job ran over " + MAX_SERVER_JOB.toHours() + " hours");
            }
            // Also after an empty page: the server holds one for up to 20 s, a broken one may answer at once.
            sleeper.sleep(POLL_PAUSE, c.job);
        }
    }

    /** A check of a host this job did not ask about is dropped: it would become a row, issues and a site map item. */
    private void accept(Run c, Check check) throws Stop {
        Optional<String> host = HostNames.normalize(check.domain());
        if (host.isEmpty()) {
            return;
        }
        if (!asked(c, host.get())) {
            if (!c.foreignLogged) {
                c.foreignLogged = true;
                error(c, FOREIGN + host.get() + ")");
            }
            return;
        }
        // A host job may ask for more hosts than the limit; it never gets rows for others.
        if (!c.rows.containsKey(host.get()) && c.rows.size() >= Math.max(MAX_ROWS, c.sent.size())) {
            throw unexpected(c, "the server sent checks of more than " + MAX_ROWS + " hosts");
        }
        store.apply(c.job.domain(), check, Instant.now()).ifPresent(row -> c.rows.put(row.host(), row));
    }

    private static boolean asked(Run c, String host) {
        Optional<String> domain = HostNames.normalize(c.job.domain());
        return domain.isPresent() ? HostNames.within(host, domain.get()) : c.sent.contains(host);
    }

    /** Known job events; a malformed one goes to the Errors tab and is skipped. */
    private Optional<ServerEvent> parse(Run c, JobEvent e) {
        try {
            return ServerEvent.parse(e);
        } catch (MalformedEventException m) {
            c.malformed++;
            if (c.malformed <= MALFORMED_LOGGED) {
                error(c, "Hirdman Radar: " + m.getMessage());
            } else if (c.malformed == MALFORMED_LOGGED + 1) {
                error(c, "Hirdman Radar: more malformed events from the server were skipped without a note");
            }
            return Optional.empty();
        }
    }

    /** A poll page, or null when the server no longer knows the job (404). */
    private JobPage poll(Run c, String id, int after) throws Stop, InterruptedException {
        return call(c, r -> r.poll(id, after), true, null);
    }

    private <T> T call(Run c, ApiCall<T> call) throws Stop, InterruptedException {
        return call(c, call, false, null);
    }

    /**
     * Calls until an answer, retrying per the policy. {@code poll}: a 404 returns null, waits stay short and an
     * unreadable answer is tried again. {@code lateAnswer} gets the answer of a call a cancel left behind.
     */
    private <T> T call(Run c, ApiCall<T> call, boolean poll, Consumer<T> lateAnswer) throws Stop, InterruptedException {
        while (true) {
            checkCancelled(c);
            checkPrivate(c);
            try {
                T value = send(c, call, lateAnswer);
                // Any answer is progress: the 429 budget limits waiting without one, so a long check spans hours.
                c.attempts = 0;
                c.waitedOn429 = Duration.ZERO;
                return value;
            } catch (ApiException e) {
                checkCancelled(c);
                if (poll && e.kind() == ApiException.Kind.HTTP && e.status() == 404) {
                    return null;
                }
                retryOrFail(c, e, poll);
            }
        }
    }

    /** Runs one call off the worker thread and waits for it; a cancel or an interrupt stops the wait at once. */
    private <T> T send(Run c, ApiCall<T> call, Consumer<T> lateAnswer) throws ApiException, Stop, InterruptedException {
        Radar r = c.radar;
        AtomicBoolean abandoned = new AtomicBoolean();
        FutureTask<T> task = new FutureTask<>(() -> {
            T value = call.call(r);
            if (abandoned.get() && lateAnswer != null) {
                lateAnswer.accept(value);
            }
            return value;
        });
        calls.execute(task);
        try {
            while (true) {
                try {
                    return task.get(CANCEL_CHECK.toNanos(), TimeUnit.NANOSECONDS);
                } catch (TimeoutException e) {
                    if (c.token.cancelled()) {
                        abandon(task, abandoned, lateAnswer);
                        throw new Stop();
                    }
                }
            }
        } catch (InterruptedException e) {
            abandon(task, abandoned, lateAnswer);
            throw e;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ApiException a) {
                throw a;
            }
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new IllegalStateException(cause);
        }
    }

    /** Stops waiting for a call; an answer that has just come is still handed to {@code lateAnswer}. */
    private static <T> void abandon(FutureTask<T> task, AtomicBoolean abandoned, Consumer<T> lateAnswer) {
        abandoned.set(true);
        if (task.cancel(true) || lateAnswer == null) {
            return;
        }
        try {
            lateAnswer.accept(task.get());
        } catch (ExecutionException | CancellationException | InterruptedException e) {
            // No answer to hand over; get() on a finished task never waits.
        }
    }

    private void retryOrFail(Run c, ApiException e, boolean poll) throws Stop, InterruptedException {
        int max = poll && e.kind() == ApiException.Kind.MALFORMED
                ? Math.min(c.o.maxAttempts(), RetryPolicy.MALFORMED_POLL_ATTEMPTS)
                : c.o.maxAttempts();
        switch (RetryPolicy.decide(e, c.attempts, max, c.waitedOn429, c.o.server().getHost(), random, poll)) {
            case RetryPolicy.Fail f -> {
                error(c, "Hirdman Radar: " + subject(c.job) + ": " + e.getMessage());
                throw fail(c, f.reason());
            }
            case RetryPolicy.Retry r -> waitToRetry(c, r, max);
        }
    }

    private void waitToRetry(Run c, RetryPolicy.Retry r, int maxAttempts) throws Stop, InterruptedException {
        String text = switch (r.kind()) {
            case BACKOFF -> StatusText.retrying(r.reason(), r.after(), c.attempts + 1, maxAttempts);
            case RATE_LIMIT -> StatusText.rateLimited(r.after());
            case HOURLY_LIMIT -> StatusText.hourlyLimit(r.after());
            case BUSY -> StatusText.busy(r.after());
        };
        if (r.countsAsAttempt()) {
            c.attempts++;
        } else {
            c.waitedOn429 = c.waitedOn429.plus(r.after());
        }
        c.job.update(JobState.RETRYING, text);
        sleeper.sleep(r.after(), c.job);
        checkCancelled(c);
        running(c);
    }

    private void finish(Run c, boolean savedScan, String tail) {
        int hosts = c.rows.size();
        int leaks = (int) c.rows.values().stream().filter(HostResult::hasLeaks).count();
        int unchecked = (int) c.rows.values().stream().filter(r -> r.status() == HostStatus.NOT_CHECKED).count();
        String done;
        if (c.hourlyCut) {
            // The server stopped at the hourly limit: the unchecked hosts did not fail.
            done = StatusText.doneAtHourlyLimit(hosts, leaks, unchecked, savedScan);
            tail = StatusText.HOURLY_CUT + tail;
        } else {
            done = StatusText.done(hosts, leaks, unchecked, savedScan);
        }
        // The saved-scan note ends with its own period.
        if (done.endsWith(".") && tail.startsWith(".")) {
            tail = tail.substring(1);
        }
        c.job.update(JobState.DONE, done + tail);
        String counted = c.job.domain() == null ? "" : ", " + StatusText.hosts(hosts);
        event(c, "Hirdman Radar: finished " + subject(c.job) + counted + ", " + leaks + " with leaks");
    }

    private List<String> recheckList(Run c) {
        if (c.job.recheck() || !c.o.recheckNotChecked() || c.job.state() != JobState.DONE) {
            return List.of();
        }
        return c.rows.values().stream().filter(r -> r.status() == HostStatus.NOT_CHECKED).map(HostResult::host).toList();
    }

    private String validDomain(Run c) throws Stop {
        Optional<String> d = HostNames.normalize(c.job.domain());
        if (d.isEmpty()) {
            throw fail(c, "Not a valid domain name");
        }
        return d.get();
    }

    private void running(Run c) {
        c.job.update(JobState.RUNNING, c.runningStatus);
    }

    private Stop fail(Run c, String reason) {
        c.job.update(JobState.FAILED, StatusText.failed(reason));
        event(c, "Hirdman Radar: " + subject(c.job) + FAILED + reason);
        deleteLive(c);
        return new Stop();
    }

    /** The server sent more than a job can hold: the job ends and nothing more is added. */
    private Stop unexpected(Run c, String why) {
        error(c, "Hirdman Radar: " + subject(c.job) + ": " + why);
        return fail(c, UNEXPECTED);
    }

    /** A failed run frees the slot its server job holds; a cancel does that itself, a Private project sends nothing. */
    private void deleteLive(Run c) {
        CancelToken.ServerJob live = c.token.serverJob();
        if (live == null || c.token.cancelled() || offNow()) {
            return;
        }
        c.token.serverJob(null);
        deleteLater(live.radar(), live.id(), FAIL_DELETE_TIMEOUT);
    }

    private boolean offNow() {
        try {
            return options.get().offForProject();
        } catch (RuntimeException e) {
            return true;
        }
    }

    private void deleteLater(Radar server, String id, Duration timeout) {
        try {
            calls.execute(() -> deleteQuietly(server, id, timeout));
        } catch (RejectedExecutionException e) {
            // Unloading: the server cancels a job nobody polls within a minute.
        }
    }

    /** True for the event a failed job sends; Burp shows those as errors. Subjects never hold this text. */
    public static boolean isFailure(String event) {
        return event != null && event.contains(FAILED);
    }

    /** The switch is read again before every request, so ticking it stops a running job. */
    private void checkPrivate(Run c) throws Stop {
        if (options.get().offForProject()) {
            throw fail(c, OFF_MID_JOB);
        }
    }

    private static void checkCancelled(Run c) throws Stop {
        if (c.token.cancelled()) {
            throw new Stop();
        }
    }

    static void deleteQuietly(Radar radar, String serverJobId, Duration timeout) {
        if (radar == null) {
            return;
        }
        try {
            radar.deleteJob(serverJobId, timeout);
        } catch (ApiException e) {
            // Best effort: the server cancels a job nobody polls within a minute anyway.
        }
    }

    private void event(Run c, String text) {
        if (!c.token.cancelled()) {
            events.accept(text);
        }
    }

    private void error(Run c, String text) {
        if (!c.token.cancelled()) {
            errors.accept(text);
        }
    }
}
