package pro.hirdman.radar;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import pro.hirdman.radar.api.ConnectionSettings;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.RadarClient;
import pro.hirdman.radar.burp.BurpIssues;
import pro.hirdman.radar.burp.BurpSiteMap;
import pro.hirdman.radar.burp.BurpThread;
import pro.hirdman.radar.burp.BurpTransport;
import pro.hirdman.radar.burp.LoginWatch;
import pro.hirdman.radar.burp.ProjectStore;
import pro.hirdman.radar.burp.ProxyHighlight;
import pro.hirdman.radar.burp.RadarEditor;
import pro.hirdman.radar.burp.RadarMenu;
import pro.hirdman.radar.burp.RadarPayloads;
import pro.hirdman.radar.burp.RadarScanCheck;
import pro.hirdman.radar.burp.RadarSettings;
import pro.hirdman.radar.burp.ScopeIssues;
import pro.hirdman.radar.burp.TrafficWatcher;
import pro.hirdman.radar.config.ProjectSwitch;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobRunner;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.Sleeper;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.traffic.NewHostBatcher;
import pro.hirdman.radar.ui.Browser;
import pro.hirdman.radar.ui.Edt;
import pro.hirdman.radar.ui.RadarTab;

/** Burp entry point: builds the parts and hands them to Burp. Decisions live in the tested classes. */
public final class HirdmanRadar implements BurpExtension {

    /** The name in Burp's extension list and the BApp Store; the tab, menu and settings keep the short one. */
    static final String NAME = "Hirdman Radar: Subdomain Leak Check";
    /** Unload must not hold Burp up: the job queue takes up to 2 s of this, queued Burp calls the rest. */
    static final Duration UNLOAD_BUDGET = Duration.ofSeconds(4);
    static final Duration BURP_THREAD_WAIT = Duration.ofSeconds(2);
    static final String NO_ISSUES = "Hirdman Radar: Burp Suite Community Edition has no issues; the counts are in the Hirdman Radar tab";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        Logging log = api.logging();
        // Community Edition has no scanner and no issues: everything else works the same.
        boolean pro = hasScanner(api.burpSuite().version().edition());

        ProjectSwitch projectSwitch = new ProjectSwitch(api.persistence().extensionData());
        RadarSettings settings = new RadarSettings(api, projectSwitch::off, pro);
        ProjectStore project = new ProjectStore(api.persistence().extensionData(), log::logToError);
        ResultStore store = project.load();

        BurpTransport transport = new BurpTransport(api.http(), settings::verifyTls, projectSwitch::off, log::logToError);
        Supplier<Radar> radar = () -> RadarClient.of(settings.serverUrl(), transport);
        Consumer<String> events = e -> {
            if (JobRunner.isFailure(e)) {
                log.raiseErrorEvent(e);
            } else {
                log.raiseInfoEvent(e);
            }
        };
        MetaGate gate = new MetaGate();
        // A job's client is made for the server of the settings snapshot the job runs with.
        JobRunner runner = new JobRunner(server -> new RadarClient(new ConnectionSettings(server), transport), store, gate,
                Sleeper.real(), () -> JobRunner.RunOptions.of(settings.snapshot()), events, log::logToError);
        // The queue starts working before the tab exists, so its changes reach the tab through this reference.
        AtomicReference<RadarTab> tabRef = new AtomicReference<>();
        JobQueue queue = new JobQueue(runner, job -> {
            RadarTab t = tabRef.get();
            if (t != null) {
                t.jobsChanged();
            }
            // Results cost the hourly limit: a finished job is saved at once, not on the next 30 s tick.
            if (job.state().finished()) {
                project.saveNow();
            }
        });

        // Issues and site map calls go to their own thread: job polling must never wait on Burp.
        BurpThread burpThread = new BurpThread(log::logToError);
        BurpSiteMap siteMap = new BurpSiteMap(api, burpThread);
        ToIntFunction<List<HostResult>> createIssues = pro ? issues(api, settings, store, burpThread) : noIssues(log);
        store.addCheckListener(row -> {
            if (settings.snapshot().addToSiteMap()) {
                siteMap.addFound(List.of(row.host()));
            }
        });
        store.addFoundListener(hosts -> {
            if (settings.snapshot().addToSiteMap()) {
                siteMap.addFound(hosts);
            }
        });

        RadarTab tab = Edt.call(() -> new RadarTab(api, store, queue, gate, settings::snapshot, projectSwitch, radar,
                createIssues, siteMap::addSelected, () -> BurpSiteMap.inScopeHosts(api.siteMap(), api.scope()::isInScope)));
        tabRef.set(tab);
        api.userInterface().registerSuiteTab("Hirdman Radar", tab);
        api.userInterface().registerContextMenuItemsProvider(new RadarMenu(queue, tab, tab::reveal));
        api.userInterface().registerHttpRequestEditorProvider(context -> new RadarEditor(store,
                host -> queue.checkAgain(List.of(host)), host -> RadarMenu.show(tab, tab::reveal, List.of(host)), projectSwitch::off,
                url -> Browser.open(url, log::logToError), api.userInterface()::applyThemeToComponent));

        NewHostBatcher batcher = new NewHostBatcher(Duration.ofSeconds(60), Duration.ofHours(24),
                store::lastChecked, () -> settings.snapshot().serverHost());
        TrafficWatcher traffic = new TrafficWatcher(batcher, settings::watchTraffic, queue, log::logToError, new LoginWatch(store));
        api.http().registerHttpHandler(traffic);
        api.proxy().registerResponseHandler(new ProxyHighlight(store, settings::highlightProxy, log::logToError));
        RadarPayloads.all(store::all, api.scope()::isInScope).forEach(api.intruder()::registerPayloadGeneratorProvider);
        traffic.start();
        project.start();

        api.extension().registerUnloadingHandler(() -> {
            long end = System.nanoTime() + UNLOAD_BUDGET.toNanos();
            runAll(log::logToError, traffic::close, tab::close, queue::shutdown,
                    () -> burpThread.close(left(end, BURP_THREAD_WAIT)), project::close);
        });
    }

    /** The scanner, and with it Burp's issues, are in Professional only; Burp DAST would need a mode without the tab. */
    static boolean hasScanner(BurpSuiteEdition edition) {
        return edition == BurpSuiteEdition.PROFESSIONAL;
    }

    /**
     * Professional: automatic issues on checks, login pages and scope changes, and the passive scan check; all of them
     * dedupe through one {@link BurpIssues}. Returns the row menu's action.
     */
    private static ToIntFunction<List<HostResult>> issues(MontoyaApi api, RadarSettings settings, ResultStore store,
            BurpThread burpThread) {
        Logging log = api.logging();
        BurpIssues issues = new BurpIssues(api, () -> settings.snapshot().issueOptions());
        Consumer<HostResult> auto = row -> {
            if (settings.snapshot().autoIssues()) {
                burpThread.execute(() -> issues.report(row));
            }
        };
        store.addCheckListener(auto);
        store.addLoginListener(auto);
        api.scope().registerScopeChangeHandler(new ScopeIssues(store::all, () -> settings.snapshot().autoIssues(),
                issues::reportAll, burpThread, log::logToError));
        api.scanner().registerPassiveScanCheck(new RadarScanCheck(store::host, issues::forScan, log::logToError),
                ScanCheckType.PER_HOST);
        return issues::reportAgain;
    }

    /** Community Edition: the row menu's issue action says why it creates none. */
    static ToIntFunction<List<HostResult>> noIssues(Logging log) {
        return rows -> {
            log.raiseInfoEvent(NO_ISSUES);
            return 0;
        };
    }

    /** What is left of the unload budget ending at {@code end}, at most {@code max}. */
    static Duration left(long end, Duration max) {
        long left = Math.max(0, end - System.nanoTime());
        return left < max.toNanos() ? Duration.ofNanos(left) : max;
    }

    /** Unload: a failing step must not skip the final save. */
    static void runAll(Consumer<String> error, Runnable... steps) {
        for (Runnable step : steps) {
            try {
                step.run();
            } catch (RuntimeException e) {
                error.accept("Hirdman Radar: unload step failed: " + e);
            }
        }
    }
}
