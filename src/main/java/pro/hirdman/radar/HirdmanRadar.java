package pro.hirdman.radar;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.RadarClient;
import pro.hirdman.radar.burp.BurpIssues;
import pro.hirdman.radar.burp.BurpSiteMap;
import pro.hirdman.radar.burp.BurpThread;
import pro.hirdman.radar.burp.BurpTransport;
import pro.hirdman.radar.burp.LoginWatch;
import pro.hirdman.radar.burp.ProjectStore;
import pro.hirdman.radar.burp.RadarEditor;
import pro.hirdman.radar.burp.RadarMenu;
import pro.hirdman.radar.burp.RadarSettings;
import pro.hirdman.radar.burp.ScopeIssues;
import pro.hirdman.radar.burp.TrafficWatcher;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.config.ProjectSwitch;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobRunner;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.Sleeper;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.traffic.NewHostBatcher;
import pro.hirdman.radar.ui.Edt;
import pro.hirdman.radar.ui.RadarTab;

/** Burp entry point: builds the parts and hands them to Burp. Decisions live in the tested classes. */
public final class HirdmanRadar implements BurpExtension {

    /** The name in Burp's extension list and the BApp Store; the tab, menu and settings keep the short one. */
    static final String NAME = "Hirdman Radar: Subdomain Leak Check";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        Logging log = api.logging();

        ProjectSwitch projectSwitch = new ProjectSwitch(api.persistence().extensionData());
        RadarSettings settings = new RadarSettings(api, projectSwitch::off);
        ProjectStore project = new ProjectStore(api.persistence().extensionData(), log::logToError);
        ResultStore store = project.load();

        BurpTransport transport = new BurpTransport(api.http(), settings::verifyTls, projectSwitch::off);
        Supplier<Radar> radar = () -> RadarClient.of(settings.serverUrl(), transport);
        Consumer<String> events = e -> {
            if (JobRunner.isFailure(e)) {
                log.raiseErrorEvent(e);
            } else {
                log.raiseInfoEvent(e);
            }
        };
        MetaGate gate = new MetaGate();
        JobRunner runner = new JobRunner(radar, store, gate, Sleeper.real(),
                () -> JobRunner.RunOptions.of(settings.snapshot()), events, log::logToError);
        // The queue starts working before the tab exists, so its changes reach the tab through this reference.
        AtomicReference<RadarTab> tabRef = new AtomicReference<>();
        JobQueue queue = new JobQueue(runner, radar, job -> {
            RadarTab t = tabRef.get();
            if (t != null) {
                t.jobsChanged();
            }
            // Results cost the hourly limit: a finished job is saved at once, not on the next 30 s tick.
            if (job.state().finished()) {
                project.saveNow();
            }
        });

        BurpIssues issues = new BurpIssues(api, () -> settings.snapshot().issueOptions());
        // Issues and site map calls go to their own thread: job polling must never wait on Burp.
        BurpThread burpThread = new BurpThread(log::logToError);
        BurpSiteMap siteMap = new BurpSiteMap(api, burpThread);
        store.addCheckListener(row -> {
            Options o = settings.snapshot();
            if (o.autoIssues()) {
                burpThread.execute(() -> issues.report(row));
            }
            if (o.addToSiteMap()) {
                siteMap.addFound(List.of(row.host()));
            }
        });
        api.scope().registerScopeChangeHandler(new ScopeIssues(store::all, () -> settings.snapshot().autoIssues(),
                issues::reportAll, burpThread, log::logToError));
        store.addFoundListener(hosts -> {
            if (settings.snapshot().addToSiteMap()) {
                siteMap.addFound(hosts);
            }
        });

        RadarTab tab = Edt.call(() -> new RadarTab(api, store, queue, gate, settings::snapshot, projectSwitch, radar,
                issues::reportAgain, siteMap::addSelected, () -> BurpSiteMap.inScopeHosts(api.siteMap(), api.scope()::isInScope)));
        tabRef.set(tab);
        api.userInterface().registerSuiteTab("Hirdman Radar", tab);
        api.userInterface().registerContextMenuItemsProvider(new RadarMenu(queue, tab, tab::reveal));
        api.userInterface().registerHttpRequestEditorProvider(context -> new RadarEditor(store,
                host -> queue.checkAgain(List.of(host)), api.userInterface()::applyThemeToComponent));

        NewHostBatcher batcher = new NewHostBatcher(Duration.ofSeconds(60), Duration.ofHours(24),
                store::lastChecked, () -> settings.snapshot().serverHost());
        store.addLoginListener(row -> {
            if (settings.snapshot().autoIssues()) {
                burpThread.execute(() -> issues.report(row));
            }
        });
        TrafficWatcher traffic = new TrafficWatcher(batcher, settings::watchTraffic, queue, log::logToError, new LoginWatch(store));
        api.http().registerHttpHandler(traffic);
        traffic.start();
        project.start();

        api.extension().registerUnloadingHandler(() -> runAll(log::logToError, traffic::close, tab::close, queue::shutdown,
                burpThread::close, project::close));
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
