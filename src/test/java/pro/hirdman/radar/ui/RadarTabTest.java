package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.scope.ScopeChangeHandler;
import burp.api.montoya.ui.UserInterface;
import java.awt.Component;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.JobPage;
import pro.hirdman.radar.api.JobRequest;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.api.SubdomainList;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.config.ProjectSwitch;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobRunner;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.Sleeper;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.Risk;

class RadarTabTest {

    static final String EMPTY = "No results yet. Enter a domain above, or right-click a host in Target, Proxy or Repeater "
            + "and choose Extensions > Hirdman Radar.";
    static final String LIMITS = "Without a key: up to 50 hosts per check and 300 hosts per hour from your address.";
    static final Meta META = new Meta(1, "0.1.0", "anonymous", new Meta.Limits(50, 1.5, 300),
            new Meta.Notes("db", "cov", "Counts only, from the server."));

    final ResultStore store = new ResultStore();
    final MetaGate gate = new MetaGate();
    // An invalid server makes every queued job fail at once, so nothing reaches the network.
    final JobRunner runner = new JobRunner(() -> null, store, gate, Sleeper.real(), this::runOptions, e -> { }, e -> { });
    /** While set, the queue's worker waits in its job, so the job stays active. */
    volatile java.util.concurrent.CountDownLatch hold;

    JobRunner.RunOptions runOptions() {
        java.util.concurrent.CountDownLatch h = hold;
        if (h != null && Thread.currentThread().getName().equals("hirdman-radar-jobs")) {
            try {
                h.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return new JobRunner.RunOptions(null, "test", false, 5, true);
    }
    final JobQueue queue = new JobQueue(runner, () -> null, j -> { });

    final Set<String> scope = new HashSet<>();
    final List<String> included = new CopyOnWriteArrayList<>();
    final List<String> infos = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    final List<List<HostResult>> reported = new ArrayList<>();
    final List<List<String>> siteMapped = new ArrayList<>();
    final List<ScopeChangeHandler> scopeHandlers = new CopyOnWriteArrayList<>();
    final AtomicReference<Options> options = new AtomicReference<>(Options.defaults());
    final Map<String, Boolean> projectData = new HashMap<>();
    final ProjectSwitch projectSwitch = new ProjectSwitch(fake(PersistedObject.class, (m, a) -> switch (m) {
        case "getBoolean" -> projectData.get((String) a[0]);
        case "setBoolean" -> {
            projectData.put((String) a[0], (Boolean) a[1]);
            yield null;
        }
        default -> pro.hirdman.radar.burp.Fakes.DEFAULT;
    }));
    final AtomicInteger metaCalls = new AtomicInteger();
    final AtomicReference<Object> metaAnswer = new AtomicReference<>(META);
    final Map<String, Boolean> prefs = new HashMap<>();
    final List<String> scopeHosts = new ArrayList<>();
    final AtomicInteger walks = new AtomicInteger();

    final MontoyaApi api = fake(MontoyaApi.class, Map.of(
            "userInterface", fake(UserInterface.class, Map.of()),
            "persistence", fake(Persistence.class, Map.of("preferences", fake(Preferences.class, (m, a) -> switch (m) {
                case "getBoolean" -> prefs.get((String) a[0]);
                case "setBoolean" -> {
                    prefs.put((String) a[0], (Boolean) a[1]);
                    yield null;
                }
                default -> pro.hirdman.radar.burp.Fakes.DEFAULT;
            }))),
            "scope", fake(Scope.class, (m, a) -> switch (m) {
                case "isInScope" -> scope.contains(a[0]);
                case "includeInScope" -> {
                    included.add((String) a[0]);
                    scope.add((String) a[0]);
                    yield null;
                }
                case "registerScopeChangeHandler" -> {
                    scopeHandlers.add((ScopeChangeHandler) a[0]);
                    yield fake(Registration.class, Map.of());
                }
                default -> pro.hirdman.radar.burp.Fakes.DEFAULT;
            }),
            "logging", fake(Logging.class, (m, a) -> {
                if (m.equals("raiseInfoEvent")) {
                    infos.add((String) a[0]);
                } else if (m.equals("logToError")) {
                    errors.add(String.valueOf(a[0]));
                }
                return pro.hirdman.radar.burp.Fakes.DEFAULT;
            })));

    final Radar radar = new Radar() {
        @Override
        public Meta meta() throws ApiException {
            metaCalls.incrementAndGet();
            Object a = metaAnswer.get();
            if (a instanceof ApiException e) {
                throw e;
            }
            if (a instanceof RuntimeException e) {
                throw e;
            }
            return (Meta) a;
        }

        @Override
        public SubdomainList subdomains(String domain, boolean rescan) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String startJob(JobRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public JobPage poll(String jobId, int after) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteJob(String jobId, Duration timeout) {
            throw new UnsupportedOperationException();
        }
    };

    RadarTab tab;

    RadarTab tab() {
        if (tab == null) {
            tab = new RadarTab(api, store, queue, gate, this::currentOptions, projectSwitch, () -> radar, rows -> {
                reported.add(rows);
                return 2 * rows.size();
            }, hosts -> {
                siteMapped.add(hosts);
                return "site map: " + hosts.size();
            }, this::walk, Runnable::run);
        }
        return tab;
    }

    /** What RadarSettings gives: the options with the project switch. */
    Options currentOptions() {
        Options o = options.get();
        if (!projectSwitch.off()) {
            return o;
        }
        return new Options(o.serverUrl(), o.autoIssues(), o.includeOutOfScope(), o.lowest(), o.addToSiteMap(), o.watchTraffic(),
                o.recheckNotChecked(), o.attempts(), o.alwaysRescan(), true);
    }

    List<String> walk() {
        walks.incrementAndGet();
        return List.copyOf(scopeHosts);
    }

    @AfterEach
    void tearDown() {
        if (tab != null) {
            tab.close();
        }
        queue.shutdown();
    }

    static void drainEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    void checked(String host, String severity) {
        List<Finding> f = severity == null ? List.of() : List.of(new Finding("k", severity, "tentative", "Leak", "", "", ""));
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 1, true, f), Instant.EPOCH);
    }

    void fresh(String host) {
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 0, true, List.of()), Instant.now());
    }

    void notChecked(String host) {
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 0, false, List.of()), Instant.EPOCH);
    }

    List<String> menuItems() {
        tab().prepareRowMenu();
        List<String> out = new ArrayList<>();
        for (Component c : tab().rowMenu.getComponents()) {
            if (c instanceof JMenuItem i && i.isVisible()) {
                out.add(i.getText());
            }
        }
        return out;
    }

    JMenuItem menuItem(String text) {
        tab().prepareRowMenu();
        for (Component c : tab().rowMenu.getComponents()) {
            if (c instanceof JMenuItem i && i.getText().equals(text)) {
                return i;
            }
        }
        throw new AssertionError("no item " + text);
    }

    void selectAll() {
        tab().flush();
        tab().table.selectAll();
    }

    @Test
    void emptyStateUntilThereAreResults() {
        assertEquals(EMPTY, tab().emptyLabel.getText());
        assertTrue(tab().emptyLabel.isVisible());
        checked("a.example.com", null);
        tab().flush();
        assertFalse(tab().emptyLabel.isVisible());
        assertEquals("example.com", tab().model.domain());
        assertEquals("1 host, 0 with leaks", tab().summaryLabel.getText());
    }

    @Test
    void enterInTheDomainFieldChecksForLeaks() {
        tab().domainField.setText(" Example.com ");
        tab().domainField.postActionEvent();
        List<Job> jobs = queue.jobs();
        assertEquals(1, jobs.size());
        assertEquals(JobKind.FIND_AND_CHECK, jobs.get(0).kind());
        assertEquals("example.com", jobs.get(0).domain());
        assertFalse(jobs.get(0).rescan());
        assertEquals("example.com", tab().model.domain());
    }

    @Test
    void findSubdomainsWithRescan() {
        tab().domainField.setText("example.com");
        tab().rescanBox.setSelected(true);
        tab().findButton.doClick(0);
        Job j = queue.jobs().get(0);
        assertEquals(JobKind.FIND_SUBDOMAINS, j.kind());
        assertTrue(j.rescan());
        // Rescan is spent on one job: the next click must not rescan by accident.
        assertFalse(tab().rescanBox.isSelected());
        tab().checkButton.doClick(0);
        assertEquals(JobKind.FIND_AND_CHECK, queue.jobs().get(1).kind());
        assertFalse(queue.jobs().get(1).rescan());
        assertEquals(RadarTab.RESCAN_TIP, tab().rescanBox.getToolTipText());
    }

    @Test
    void blankDomainQueuesNothing() {
        tab().domainField.setText("   ");
        tab().checkButton.doClick(0);
        tab().findButton.doClick(0);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void buttonsHaveMnemonics() {
        assertEquals("Find subdomains", tab().findButton.getText());
        assertEquals(KeyEvent.VK_F, tab().findButton.getMnemonic());
        assertEquals("Check for leaks", tab().checkButton.getText());
        assertEquals(KeyEvent.VK_C, tab().checkButton.getMnemonic());
        assertEquals("Rescan", tab().rescanBox.getText());
    }

    @Test
    void rowMenuAlwaysOffersIssues() {
        // Rows checked before the scope or the settings changed can get their issues without a new check.
        checked("a.example.com", "high");
        selectAll();
        assertEquals(List.of("Check selected hosts", "Check again", "Re-check failed", "Add selected to scope", "Add selected to site map",
                "Create issues for selected hosts", "Copy hosts", "Copy as CSV", "Remove from results"), menuItems());
        options.set(new Options(Options.DEFAULT_SERVER, false, false, Risk.LOW, true, false, true, 5, false));
        assertTrue(menuItems().contains("Create issues for selected hosts"));
    }

    @Test
    void selectionDrivesTheMenu() {
        checked("a.example.com", null);
        tab().flush();
        assertFalse(menuItem("Check selected hosts").isEnabled());
        assertFalse(menuItem("Re-check failed").isEnabled());
        tab().table.selectAll();
        assertTrue(menuItem("Copy as CSV").isEnabled());
        notChecked("b.example.com");
        tab().flush();
        assertTrue(menuItem("Re-check failed").isEnabled());
    }

    @Test
    void addSelectedToScopeUsesTheHttpsRoot() {
        checked("a.example.com", null);
        selectAll();
        assertEquals("out", tab().model.getValueAt(0, ResultsTableModel.SCOPE));
        menuItem("Add selected to scope").doClick(0);
        assertEquals(List.of("https://a.example.com/"), included);
        assertEquals("in", tab().model.getValueAt(0, ResultsTableModel.SCOPE));
    }

    @Test
    void addSelectedToSiteMapLogsWhatHappened() {
        checked("a.example.com", null);
        selectAll();
        menuItem("Add selected to site map").doClick(0);
        assertEquals(List.of(List.of("a.example.com")), siteMapped);
        assertEquals(List.of("site map: 1"), infos);
    }

    JMenuItem exportItem(String text) {
        for (Component c : tab().exportMenu.getComponents()) {
            if (c instanceof JMenuItem i && i.getText().equals(text)) {
                return i;
            }
        }
        throw new AssertionError("no export item " + text);
    }

    @Test
    void exportWritesTheRowsShown(@TempDir Path dir) throws Exception {
        checked("a.example.com", "high");
        notChecked("b.example.com");
        tab().flush();
        Path out = dir.resolve("r.json");
        List<String> asked = new ArrayList<>();
        tab().saveDialog = name -> {
            asked.add(name);
            return Optional.of(out);
        };
        assertEquals("Export", tab().exportButton.getText());
        exportItem("JSON...").doClick(0);
        assertEquals(List.of("hirdman-radar-example.com.json"), asked);
        String json = Files.readString(out);
        assertTrue(json.contains("\"host\": \"a.example.com\""), json);
        assertTrue(json.contains("\"host\": \"b.example.com\""), json);
        assertTrue(json.contains("\"report_url\": \"https://scan.hirdman.pro/?domain=example.com\""), json);
        assertEquals(List.of("Hirdman Radar: exported 2 hosts to " + out), infos);
    }

    @Test
    void copySummaryCopiesTheWholeDomainWhateverTheFilter() {
        checked("a.example.com", "high");
        notChecked("b.example.com");
        tab().flush();
        tab().filterBox.setSelectedItem(ResultsFilter.FAILED);
        List<String> copied = new ArrayList<>();
        tab().clipboard = copied::add;
        exportItem("Copy summary").doClick(0);
        assertEquals(1, copied.size());
        assertTrue(copied.get(0).startsWith("## Hirdman Radar: example.com\n\n2 hosts, 1 with leaks, 1 failed."), copied.get(0));
        assertTrue(copied.get(0).contains("| a.example.com | High |"), copied.get(0));
        assertTrue(copied.get(0).contains("https://scan.hirdman.pro/?domain=example.com"), copied.get(0));
    }

    @Test
    void csvExportToAPlaceThatCannotBeWrittenIsLoggedAndSaid(@TempDir Path dir) throws Exception {
        checked("a.example.com", "high");
        tab().flush();
        tab().saveDialog = name -> Optional.of(dir);
        List<String> said = new ArrayList<>();
        tab().message = said::add;
        exportItem("CSV...").doClick(0);
        drainEdt();
        assertEquals(List.of(RadarTab.EXPORT_FAILED), said);
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: export to " + dir + " failed: "), errors.get(0));
    }

    @Test
    void aCancelledExportWritesNothing() {
        checked("a.example.com", "high");
        tab().flush();
        tab().saveDialog = name -> Optional.empty();
        exportItem("CSV...").doClick(0);
        assertEquals(List.of(), infos);
        assertEquals(List.of(), errors);
    }

    @Test
    void checkSelectedAndRecheckQueueHostChecks() {
        checked("a.example.com", null);
        notChecked("b.example.com");
        notChecked("c.example.com");
        tab().flush();
        tab().table.setRowSelectionInterval(0, 0);
        menuItem("Check selected hosts").doClick(0);
        menuItem("Re-check failed").doClick(0);
        List<Job> jobs = queue.jobs();
        assertEquals(List.of(JobKind.CHECK_HOSTS, JobKind.CHECK_HOSTS), jobs.stream().map(Job::kind).toList());
        assertEquals(List.of("a.example.com"), jobs.get(0).hosts());
        assertEquals(List.of("b.example.com", "c.example.com"), jobs.get(1).hosts());
    }

    @Test
    void checkingMoreRowsThanOneServerCheckAsksFirst() {
        for (int i = 0; i < 51; i++) {
            notChecked("h" + i + ".example.com");
        }
        List<String> asked = new ArrayList<>();
        tab().confirm = q -> {
            asked.add(q);
            return false;
        };
        tab().flush();
        menuItem("Re-check failed").doClick(0);
        tab().table.selectAll();
        menuItem("Check selected hosts").doClick(0);
        menuItem("Check again").doClick(0);
        assertEquals(java.util.Collections.nCopies(3, "Send 51 host names to the Hirdman Radar server for a leak check?"), asked);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void theQuestionCountsOnlyHostsThatWillBeSent() {
        for (int i = 0; i < 80; i++) {
            if (i < 20) {
                fresh("h" + i + ".example.com");
            } else {
                notChecked("h" + i + ".example.com");
            }
        }
        List<String> asked = new ArrayList<>();
        tab().confirm = q -> {
            asked.add(q);
            return false;
        };
        tab().flush();
        selectAll();
        menuItem("Check selected hosts").doClick(0);
        menuItem("Check again").doClick(0);
        assertEquals(List.of("Send 60 host names to the Hirdman Radar server for a leak check?",
                "Send 80 host names to the Hirdman Radar server for a leak check?"), asked);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void checkingOnlyFreshRowsAsksNothing() {
        for (int i = 0; i < 60; i++) {
            fresh("h" + i + ".example.com");
        }
        List<String> asked = new ArrayList<>();
        tab().confirm = q -> {
            asked.add(q);
            return false;
        };
        tab().flush();
        selectAll();
        menuItem("Check selected hosts").doClick(0);
        assertEquals(List.of(), asked);
        assertEquals(1, queue.jobs().size());
    }

    @Test
    void checkAgainQueuesAForcedCheckOfTheSelectedRows() {
        checked("a.example.com", null);
        checked("b.example.com", "high");
        tab().flush();
        assertFalse(menuItem("Check again").isEnabled());
        selectAll();
        assertTrue(menuItem("Check again").isEnabled());
        menuItem("Check again").doClick(0);
        Job job = queue.jobs().get(0);
        assertTrue(job.force());
        assertEquals(java.util.Set.of("a.example.com", "b.example.com"), java.util.Set.copyOf(job.hosts()));
    }

    @Test
    void checkInScopeHostsAsksWithTheCountsThenQueues() throws Exception {
        scopeHosts.addAll(List.of("a.example.com", "b.example.com", "c.example.com"));
        store.apply("example.com", new Check(false, "b.example.com", 0, 0, 0, 0, 1, true, List.of()), Instant.now());
        // hosts_left is asked afresh: the tab's /meta answer may be hours old.
        metaAnswer.set(new Meta(1, "0.1.0", "anonymous", new Meta.Limits(50, 1.5, 300, 120), META.notes()));
        List<String> asked = new ArrayList<>();
        AtomicReference<Boolean> agree = new AtomicReference<>(false);
        tab().confirm = q -> {
            asked.add(q);
            return agree.get();
        };
        tab().scopeButton.doClick(0);
        drainEdt();
        assertEquals(List.of("Check 2 in-scope hosts from the site map for leaks? 1 host checked in the last 24 h is skipped. "
                + "Your address can check 120 more hosts this hour."), asked);
        assertTrue(queue.jobs().isEmpty());
        assertTrue(tab().scopeButton.isEnabled());
        agree.set(true);
        tab().scopeButton.doClick(0);
        drainEdt();
        assertEquals(List.of(JobKind.CHECK_HOSTS), queue.jobs().stream().map(Job::kind).toList());
        assertEquals(List.of("a.example.com", "c.example.com"), queue.jobs().get(0).hosts());
    }

    @Test
    void checkInScopeHostsSaysWhenThereIsNothingToSend() throws Exception {
        List<String> said = new ArrayList<>();
        tab().message = said::add;
        tab().confirm = q -> {
            throw new AssertionError(q);
        };
        tab().scopeButton.doClick(0);
        drainEdt();
        Options d = Options.defaults();
        options.set(new Options(d.serverUrl(), true, true, Risk.LOW, true, false, true, 5, false, true));
        tab().scopeButton.doClick(0);
        drainEdt();
        assertEquals(List.of("No in-scope host names in the site map.", ServerLine.OFF_FOR_PROJECT.text()), said);
        assertEquals(1, walks.get());
        assertEquals(0, metaCalls.get());
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void removeFromResultsDropsTheRows() {
        checked("a.example.com", null);
        checked("b.example.com", null);
        tab().flush();
        tab().table.setRowSelectionInterval(0, 0);
        menuItem("Remove from results").doClick(0);
        assertTrue(store.host("a.example.com").isEmpty());
        assertTrue(store.host("b.example.com").isPresent());
    }

    @Test
    void createIssuesReportsTheSelectedRows() {
        options.set(new Options(Options.DEFAULT_SERVER, false, false, Risk.LOW, true, false, true, 5, false));
        checked("a.example.com", "high");
        checked("b.example.com", null);
        selectAll();
        menuItem("Create issues for selected hosts").doClick(0);
        assertEquals(1, reported.size(), "one click asks Burp for its issues once");
        assertEquals(List.of("a.example.com", "b.example.com"), reported.get(0).stream().map(HostResult::host).toList());
        assertEquals(List.of("Hirdman Radar: created 4 issues for 2 hosts. " + HINT_1), infos);
    }

    static final String HINT_1 = "1 host with leaks is out of Burp's scope, so it gets no issues. Add it to scope,"
            + " or tick \"Include out-of-scope hosts\" in Settings > Extensions > Hirdman Radar.";
    static final String HINT_2 = "2 hosts with leaks are out of Burp's scope, so they get no issues. Add them to scope,"
            + " or tick \"Include out-of-scope hosts\" in Settings > Extensions > Hirdman Radar.";

    @Test
    void aLineSaysWhyHostsWithLeaksOutOfScopeGetNoIssues() {
        options.set(new Options(Options.DEFAULT_SERVER, true, false, Risk.LOW, true, false, true, 5, false));
        checked("a.example.com", "high");
        checked("b.example.com", "high");
        checked("c.example.com", null);
        selectAll();
        assertTrue(tab().scopeHint.isVisible());
        assertEquals(HINT_2, tab().scopeHint.getText());
        assertEquals(Boolean.TRUE, tab().scopeHint.getClientProperty("html.disable"));

        scope.add("https://a.example.com/");
        scopeHandlers.forEach(h -> h.scopeChanged(null));
        tab().flush();
        assertEquals(HINT_1, tab().scopeHint.getText());

        scope.add("https://b.example.com/");
        scopeHandlers.forEach(h -> h.scopeChanged(null));
        tab().flush();
        assertFalse(tab().scopeHint.isVisible());
    }

    @Test
    void noScopeLineWhenIssuesDoNotDependOnScope() {
        checked("a.example.com", "high");
        selectAll();
        assertFalse(tab().scopeHint.isVisible());
        options.set(new Options(Options.DEFAULT_SERVER, false, false, Risk.LOW, true, false, true, 5, false));
        tab().flush();
        assertFalse(tab().scopeHint.isVisible());
    }

    @Test
    void oneIssueForOneHostIsSingular() {
        tab = new RadarTab(api, store, queue, gate, options::get, projectSwitch, () -> radar, List::size, hosts -> "", this::walk, Runnable::run);
        options.set(new Options(Options.DEFAULT_SERVER, false, false, Risk.LOW, true, false, true, 5, false));
        scope.add("https://a.example.com/");
        checked("a.example.com", "high");
        selectAll();
        menuItem("Create issues for selected hosts").doClick(0);
        assertEquals(List.of("Hirdman Radar: created 1 issue for 1 host"), infos);
    }

    @Test
    void ticksApplyStoreAndQueueChanges() {
        tab().shown = () -> true;
        tab().tick();
        assertTrue(tab().emptyLabel.isVisible());
        checked("a.example.com", null);
        tab().tick();
        assertFalse(tab().emptyLabel.isVisible());
        queue.submit(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false);
        tab().tick();
        assertFalse(tab().jobsScroll.isVisible());
        tab().jobsChanged();
        tab().tick();
        assertTrue(tab().jobsScroll.isVisible());
    }

    @Test
    void aHiddenTabWaitsUntilItIsShown() {
        tab().shown = () -> false;
        checked("a.example.com", null);
        tab().tick();
        assertTrue(tab().emptyLabel.isVisible());
        tab().shown = () -> true;
        tab().tick();
        assertFalse(tab().emptyLabel.isVisible());
    }

    @Test
    void aScopeChangeInBurpReachesTheScopeColumn() {
        checked("a.example.com", null);
        selectAll();
        assertEquals("out", tab().model.getValueAt(0, ResultsTableModel.SCOPE));
        scope.add("https://a.example.com/");
        scopeHandlers.forEach(h -> h.scopeChanged(null));
        tab().flush();
        assertEquals("in", tab().model.getValueAt(0, ResultsTableModel.SCOPE));
    }

    @Test
    void middleClickLeavesTheSelection() {
        checked("a.example.com", null);
        checked("b.example.com", null);
        tab().flush();
        tab().table.setRowSelectionInterval(0, 0);
        tab().table.dispatchEvent(new java.awt.event.MouseEvent(tab().table, java.awt.event.MouseEvent.MOUSE_PRESSED, 0,
                java.awt.event.InputEvent.BUTTON2_DOWN_MASK, 5, tab().table.getRowHeight() + 1, 1, false,
                java.awt.event.MouseEvent.BUTTON2));
        assertEquals(List.of("a.example.com"), tab().table.selected().stream().map(HostResult::host).toList());
    }

    @Test
    void serverCheckShowsTheLimitsAndTheNote() throws Exception {
        assertEquals("Counts only: no accounts, passwords, raw records or dumps. Partial check, about a third of a full HIRDMAN review.",
                tab().footerLabel.getText());
        tab().checkServer();
        drainEdt();
        assertEquals(LIMITS, tab().serverLabel.getText());
        assertFalse(tab().tryAgainButton.isVisible());
        assertEquals("Counts only, from the server. Partial check, about a third of a full HIRDMAN review.", tab().footerLabel.getText());
        assertEquals(META, gate.last().orElseThrow());
    }

    @Test
    void unreachableServerOffersTryAgain() throws Exception {
        metaAnswer.set(ApiException.unreachable(new IOException("refused")));
        tab().checkServer();
        drainEdt();
        assertEquals("Cannot reach scan.hirdman.pro. The plugin needs internet access, directly or through Burp's upstream proxy. Behind a proxy that re-signs HTTPS, turn off the certificate check in Settings > Extensions > Hirdman Radar.",
                tab().serverLabel.getText());
        assertTrue(tab().tryAgainButton.isVisible());
        metaAnswer.set(META);
        tab().tryAgainButton.doClick(0);
        drainEdt();
        assertEquals(LIMITS, tab().serverLabel.getText());
        assertFalse(tab().tryAgainButton.isVisible());
    }

    @Test
    void unexpectedServerErrorIsLoggedAndOffersTryAgain() throws Exception {
        metaAnswer.set(new IllegalStateException("boom"));
        tab().checkServer();
        drainEdt();
        assertEquals("Server check failed: unexpected error. Details are in the extension's Errors tab.", tab().serverLabel.getText());
        assertTrue(tab().tryAgainButton.isVisible());
        assertEquals(List.of("Hirdman Radar: server check failed"), errors);
    }

    @Test
    void theReasonOfAFailedServerCheckIsLogged() throws Exception {
        metaAnswer.set(ApiException.malformed("no limits in /meta", null));
        tab().checkServer();
        drainEdt();
        assertEquals("Server check failed: unexpected answer.", tab().serverLabel.getText());
        assertEquals(1, errors.size(), errors.toString());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: server check failed: "), errors.get(0));
        assertTrue(errors.get(0).contains("no limits in /meta"), errors.get(0));
    }

    @Test
    void staleServerAnswerIsDropped() throws Exception {
        List<Runnable> later = new ArrayList<>();
        tab = new RadarTab(api, store, queue, gate, options::get, projectSwitch, () -> radar, rows -> 0, hosts -> "", this::walk, later::add);
        metaAnswer.set(ApiException.unreachable(new IOException("refused")));
        tab.checkServer();
        options.set(new Options("http://bad.example", true, false, Risk.LOW, true, false, true, 5, false));
        tab.checkServer();
        later.get(0).run();
        drainEdt();
        assertEquals("Server URL must start with https://", tab.serverLabel.getText());
    }

    @Test
    void rightClickSelectsTheRowUnderThePointer() {
        checked("a.example.com", null);
        checked("b.example.com", null);
        tab().flush();
        tab().table.setRowSelectionInterval(0, 0);
        int y = tab().table.getRowHeight() + 1;
        tab().table.dispatchEvent(new java.awt.event.MouseEvent(tab().table, java.awt.event.MouseEvent.MOUSE_PRESSED, 0,
                java.awt.event.InputEvent.BUTTON3_DOWN_MASK, 5, y, 1, false, java.awt.event.MouseEvent.BUTTON3));
        assertEquals(List.of("b.example.com"), tab().table.selected().stream().map(HostResult::host).toList());
        tab().table.selectAll();
        tab().table.dispatchEvent(new java.awt.event.MouseEvent(tab().table, java.awt.event.MouseEvent.MOUSE_PRESSED, 0,
                java.awt.event.InputEvent.BUTTON3_DOWN_MASK, 5, 1, 1, false, java.awt.event.MouseEvent.BUTTON3));
        assertEquals(2, tab().table.getSelectedRowCount());
    }

    @Test
    void theNoticeSaysWhatIsSentUntilGotIt() {
        assertTrue(tab().noticePanel.isVisible());
        assertEquals(List.of(
                "Hirdman Radar sends the domains and host names you pick to the radar server and gets back counts only. "
                        + "Nothing else from your project is sent.",
                "New in-scope hosts from traffic are sent only if you turn that on in Settings > Extensions > Hirdman Radar.",
                "For a project whose host names must not leave Burp, tick \"Private project\" at the bottom of this tab."),
                tab().noticeLines.stream().map(javax.swing.JLabel::getText).toList());
        tab().gotItButton.doClick();
        assertFalse(tab().noticePanel.isVisible());
        assertEquals(Map.of(RadarTab.NOTICE_SEEN, true), prefs);
        tab.close();
        tab = null;
        assertFalse(tab().noticePanel.isVisible());
    }

    @Test
    void aProjectTurnedOffIsShownWithoutAsking() throws Exception {
        Options d = Options.defaults();
        options.set(new Options(d.serverUrl(), true, false, Risk.LOW, true, false, true, 5, false, true));
        tab().checkServer();
        drainEdt();
        assertEquals(OFF_LINE, tab().serverLabel.getText());
        assertTrue(tab().tryAgainButton.isVisible());
        assertEquals(0, metaCalls.get());
    }

    static final String OFF_LINE = "Private project: nothing is sent to the radar server.";

    @Test
    void theProjectSwitchIsInTheTabAndKeptInTheProject() throws Exception {
        assertEquals("Private project: send nothing to the radar", tab().projectBox.getText());
        assertEquals("(?)", tab().projectHelp.getText());
        assertEquals(Boolean.TRUE, tab().projectHelp.getClientProperty("html.disable"));
        String tip = "For engagements where host names must not leave Burp. While ticked, this project sends nothing to "
                + "scan.hirdman.pro: no checks, no subdomain search, no traffic checks. Results already here stay. "
                + "Other projects are not affected.";
        assertEquals(tip, tab().projectBox.getToolTipText());
        assertEquals(tip, tab().projectHelp.getToolTipText());
        assertFalse(tab().projectBox.isSelected());
        drainEdt();
        int asked = metaCalls.get();
        tab().projectBox.doClick(0);
        drainEdt();
        assertTrue(projectSwitch.off());
        assertEquals(Map.of("hirdman.radar.off", true), projectData);
        assertEquals(OFF_LINE, tab().serverLabel.getText());
        assertEquals(asked, metaCalls.get());
        tab().projectBox.doClick(0);
        drainEdt();
        assertFalse(projectSwitch.off());
        assertEquals(Map.of("hirdman.radar.off", false), projectData);
        assertEquals(asked + 1, metaCalls.get());
    }

    @Test
    void aProjectSavedAsOffOpensWithTheSwitchTicked() {
        projectSwitch.set(true);
        assertTrue(tab().projectBox.isSelected());
    }

    @Test
    void turningTheProjectOffOrOnAsksAgain() throws Exception {
        tab().watchServer();
        drainEdt();
        Options d = Options.defaults();
        options.set(new Options(d.serverUrl(), true, true, Risk.LOW, true, false, true, 5, false, true));
        tab().watchServer();
        drainEdt();
        assertTrue(tab().serverLabel.getText().startsWith("Private project"), tab().serverLabel.getText());
        options.set(Options.defaults());
        tab().watchServer();
        drainEdt();
        assertEquals(2, metaCalls.get());
    }

    @Test
    void badServerUrlIsShownWithoutAsking() throws Exception {
        options.set(new Options("http://example.com", true, false, Risk.LOW, true, false, true, 5, false));
        tab().checkServer();
        drainEdt();
        assertEquals("Server URL must start with https://", tab().serverLabel.getText());
        assertEquals(0, metaCalls.get());
    }

    @Test
    void serverUrlChangeAsksAgain() throws Exception {
        tab().watchServer();
        drainEdt();
        assertEquals(1, metaCalls.get());
        tab().watchServer();
        assertEquals(1, metaCalls.get());
        options.set(new Options("https://other.example", true, false, Risk.LOW, true, false, true, 5, false));
        tab().watchServer();
        drainEdt();
        assertEquals(2, metaCalls.get());
    }

    @Test
    void metaFromAJobUpdatesTheLine() throws Exception {
        tab();
        gate.passed(java.net.URI.create("https://scan.hirdman.pro"), META);
        drainEdt();
        assertEquals(LIMITS, tab().serverLabel.getText());
    }

    @Test
    void domainAndFilterChoosersDriveTheTable() {
        checked("a.example.com", "high");
        checked("b.example.com", null);
        store.apply("other.org", new Check(false, "x.other.org", 0, 0, 0, 0, 0, true, List.of()), Instant.EPOCH);
        tab().flush();
        assertEquals(List.of("example.com", "other.org"), List.of(tab().domainBox.getItemAt(0), tab().domainBox.getItemAt(1)));
        tab().domainBox.setSelectedItem("other.org");
        assertEquals("other.org", tab().model.domain());
        tab().domainBox.setSelectedItem("example.com");
        tab().filterBox.setSelectedItem(ResultsFilter.WITH_LEAKS);
        assertEquals(1, tab().model.getRowCount());
        assertEquals(ResultsFilter.ALL, tab().filterBox.getItemAt(0));
    }

    @Test
    void jobsStripFollowsTheQueue() {
        assertFalse(tab().jobsScroll.isVisible());
        queue.submit(JobKind.FIND_SUBDOMAINS, "example.com", List.of(), false);
        tab().jobsChanged();
        tab().flush();
        assertTrue(tab().jobsScroll.isVisible());
        assertTrue(tab().jobsPanel.hasJobs());
    }

    @Test
    void theFooterShowsThePluginVersionBesideTheSiteLink() {
        assertEquals("Hirdman Radar " + pro.hirdman.radar.Version.current(), tab().versionLabel.getText());
        assertEquals("Plugin version. Quote it when you report a problem.", tab().versionLabel.getToolTipText());
        assertEquals(Boolean.TRUE, tab().versionLabel.getClientProperty("html.disable"));
        assertSame(tab().link.getParent(), tab().versionLabel.getParent());
        assertTrue(tab().versionLabel.getFont().getSize2D() < javax.swing.UIManager.getFont("Label.font").getSize2D());
    }

    @Test
    void linkIsFocusableAndNamesTheSite() {
        assertEquals("hirdman.pro", tab().link.getText());
        assertTrue(tab().link.isFocusable());
        assertEquals(Boolean.TRUE, tab().link.getClientProperty("html.disable"));
        assertEquals(Boolean.TRUE, tab().serverLabel.getClientProperty("html.disable"));
        assertEquals(Boolean.TRUE, tab().footerLabel.getClientProperty("html.disable"));
    }

    @Test
    void timerRunsOnlyWhileTheTabIsInBurp() {
        assertFalse(tab().timer.isRunning());
        assertEquals(250, tab().timer.getDelay());
        tab().timer.start();
        tab().close();
        assertFalse(tab().timer.isRunning());
    }

    @Test
    void aHostWhoseCheckFailedIsNotSkippedAsRecentlyChecked() throws Exception {
        scopeHosts.addAll(List.of("a.example.com", "b.example.com"));
        store.apply("example.com", new Check(false, "b.example.com", 0, 0, 0, 0, 0, false, List.of()), Instant.now());
        List<String> asked = new ArrayList<>();
        tab().confirm = q -> {
            asked.add(q);
            return true;
        };
        tab().scopeButton.doClick(0);
        drainEdt();
        assertTrue(asked.get(0).startsWith("Check 2 in-scope hosts from the site map for leaks?"), asked.toString());
        assertEquals(List.of("a.example.com", "b.example.com"), queue.jobs().get(0).hosts());
    }

    @Test
    void aPastedUrlBecomesItsDomain() {
        tab().domainField.setText(" https://User@VPN.Example.com:8443/login?next=/#top ");
        tab().checkButton.doClick(0);
        assertEquals("vpn.example.com", queue.jobs().get(0).domain());
        assertEquals("vpn.example.com", tab().domainField.getText());
        tab().domainField.setText("*.example.com");
        tab().findButton.doClick(0);
        assertEquals("example.com", queue.jobs().get(1).domain());
    }

    @Test
    void anAddressOrJunkInTheDomainFieldQueuesNothingAndSaysWhyUnderIt() {
        tab().message = m -> {
            throw new AssertionError("no window for a typo: " + m);
        };
        assertFalse(tab().domainHint.isVisible());
        for (String bad : List.of("10.0.0.1", "https://10.0.0.1/x", "<b>x</b>", "localhost", "http://")) {
            tab().domainField.setText(bad);
            tab().checkButton.doClick(0);
            assertEquals(RadarTab.NOT_A_DOMAIN, tab().domainHint.getText());
            assertTrue(tab().domainHint.isVisible());
        }
        assertTrue(queue.jobs().isEmpty());
        assertEquals("http://", tab().domainField.getText());
        tab().domainField.setText("example.com");
        tab().findButton.doClick(0);
        assertFalse(tab().domainHint.isVisible());
        assertEquals(1, queue.jobs().size());
    }

    @Test
    void revealShowsTheDomainOfTheFirstKnownHostAndSelectsItsRows() throws Exception {
        checked("a.example.com", "high");
        checked("b.example.com", null);
        store.apply("other.org", new Check(false, "x.other.org", 0, 0, 0, 0, 1, true,
                List.of(new Finding("k", "high", "tentative", "Leak", "", "", ""))), Instant.EPOCH);
        tab().flush();
        tab().filterBox.setSelectedItem(ResultsFilter.WITH_LEAKS);
        tab().reveal(List.of("10.0.0.1", "unknown.example.net", "X.other.org", "a.example.com"));
        assertEquals("other.org", tab().model.domain());
        assertEquals("other.org", tab().domainBox.getSelectedItem());
        assertEquals(ResultsFilter.WITH_LEAKS, tab().filterBox.getSelectedItem());
        assertEquals(List.of("x.other.org"), tab().table.selectedHosts());
        tab().reveal(List.of("b.example.com"));
        assertEquals("example.com", tab().model.domain());
        assertEquals(ResultsFilter.ALL, tab().filterBox.getSelectedItem());
        assertEquals(List.of("b.example.com"), tab().table.selectedHosts());
        tab().reveal(List.of("nothing.example.net"));
        assertEquals(List.of("b.example.com"), tab().table.selectedHosts());
    }

    @Test
    void theServerLineKeepsTryAgainInViewAndItsFullTextInATip() throws Exception {
        metaAnswer.set(ApiException.unreachable(new IOException("refused")));
        tab().checkServer();
        drainEdt();
        assertEquals(tab().serverLabel.getText(), tab().serverLabel.getToolTipText());
        java.awt.Container line = tab().serverLabel.getParent();
        java.awt.BorderLayout layout = (java.awt.BorderLayout) line.getLayout();
        assertTrue(layout.getLayoutComponent(java.awt.BorderLayout.WEST) == tab().tryAgainButton);
        assertTrue(layout.getLayoutComponent(java.awt.BorderLayout.CENTER) == tab().serverLabel);
    }

    @Test
    void anEmptyTableSaysResultsAreComingWhileAJobIsActive() {
        assertEquals(RadarTab.EMPTY, RadarTab.emptyText(List.of()));
        Job done = pro.hirdman.radar.jobs.TestJobs.job(JobKind.FIND_AND_CHECK, "example.com", List.of(),
                pro.hirdman.radar.jobs.JobState.DONE, "Done");
        Job waiting = pro.hirdman.radar.jobs.TestJobs.job(JobKind.FIND_AND_CHECK, "example.org", List.of(),
                pro.hirdman.radar.jobs.JobState.WAITING, "Waiting");
        assertEquals(RadarTab.EMPTY, RadarTab.emptyText(List.of(done)));
        assertEquals(RadarTab.WORKING, RadarTab.emptyText(List.of(done, waiting)));
        tab().flush();
        assertEquals(RadarTab.EMPTY, tab().emptyLabel.getText());
    }

    void press(int key, int modifiers) {
        Object name = tab().table.getInputMap().get(javax.swing.KeyStroke.getKeyStroke(key, modifiers));
        assertTrue(name != null, "no binding for " + KeyEvent.getKeyText(key));
        tab().table.getActionMap().get(name).actionPerformed(new java.awt.event.ActionEvent(tab().table, 0, ""));
    }

    @Test
    void theShortcutCopiesTheSelectedHostNames() {
        checked("a.example.com", null);
        checked("b.example.com", null);
        tab().flush();
        List<String> copied = new ArrayList<>();
        tab().clipboard = copied::add;
        tab().table.setRowSelectionInterval(0, 1);
        press(KeyEvent.VK_C, RadarTab.shortcutMask());
        assertEquals(List.of("a.example.com\nb.example.com"), copied);
        assertEquals(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_C, RadarTab.shortcutMask()),
                menuItem("Copy hosts").getAccelerator());
        assertEquals(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), menuItem("Remove from results").getAccelerator());
    }

    @Test
    void deleteRemovesOneRowAtOnceAndAsksBeforeSeveral() {
        checked("a.example.com", null);
        checked("b.example.com", null);
        checked("c.example.com", null);
        tab().flush();
        List<String> asked = new ArrayList<>();
        AtomicReference<Boolean> agree = new AtomicReference<>(false);
        tab().confirmRemove = q -> {
            asked.add(q);
            return agree.get();
        };
        tab().table.setRowSelectionInterval(0, 0);
        press(KeyEvent.VK_DELETE, 0);
        assertTrue(store.host("a.example.com").isEmpty());
        assertTrue(asked.isEmpty());
        tab().flush();
        tab().table.setRowSelectionInterval(0, 1);
        press(KeyEvent.VK_BACK_SPACE, 0);
        assertEquals(List.of("Remove 2 hosts from the results?"), asked);
        assertEquals(2, store.all().size());
        menuItem("Remove from results").doClick(0);
        assertEquals(2, asked.size());
        assertEquals(2, store.all().size());
        agree.set(true);
        menuItem("Remove from results").doClick(0);
        assertTrue(store.all().isEmpty());
    }

    void scannedWithRest(int rest) {
        store.apply("example.com", new Check(false, "example.com", 0, 0, 0, 0, 0, true, List.of()), Instant.now());
        store.found("example.com", IntStream.range(0, rest).mapToObj(i -> "r" + i + ".example.com").toList());
    }

    @Test
    void uncheckedSubdomainsOfAScannedDomainGetALineAndAButton() throws Exception {
        tab().confirm = q -> {
            throw new AssertionError("no question for a few hosts: " + q);
        };
        assertFalse(tab().restPanel.isVisible());
        scannedWithRest(2);
        tab().flush();
        assertTrue(tab().restPanel.isVisible());
        assertEquals("2 subdomains of example.com are not checked yet.", tab().restLabel.getText());
        assertEquals("Check them", tab().restButton.getText());
        tab().restButton.doClick(0);
        drainEdt();
        assertEquals(List.of(JobKind.CHECK_HOSTS), queue.jobs().stream().map(Job::kind).toList());
        assertEquals(List.of("r0.example.com", "r1.example.com"), queue.jobs().get(0).hosts());
        assertEquals(0, metaCalls.get());
    }

    @Test
    void manyUncheckedSubdomainsAskWithTheHourlyLimit() throws Exception {
        scannedWithRest(60);
        tab().flush();
        metaAnswer.set(new Meta(1, "0.1.0", "anonymous", new Meta.Limits(50, 1.5, 300, 120), META.notes()));
        List<String> asked = new ArrayList<>();
        tab().confirm = q -> {
            asked.add(q);
            return false;
        };
        tab().restButton.doClick(0);
        drainEdt();
        assertEquals(List.of("Check 60 subdomains of example.com that are not checked yet? Your address can check 120 more"
                + " hosts this hour."), asked);
        assertTrue(queue.jobs().isEmpty());
        assertTrue(tab().restButton.isEnabled());
    }

    @Test
    void foundSubdomainsOfAnUnscannedDomainGetNoLine() {
        store.found("example.com", List.of("a.example.com"));
        tab().flush();
        assertFalse(tab().restPanel.isVisible());
    }

    @Test
    void checkThemSendsNothingInAPrivateProject() throws Exception {
        scannedWithRest(2);
        tab().flush();
        Options d = Options.defaults();
        options.set(new Options(d.serverUrl(), true, true, Risk.LOW, true, false, true, 5, false, true));
        List<String> said = new ArrayList<>();
        tab().message = said::add;
        tab().restButton.doClick(0);
        drainEdt();
        assertEquals(List.of(ServerLine.OFF_FOR_PROJECT.text()), said);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void rescanStaysTickedWhenTheClickJoinsAJobThatUsesTheSavedScan() throws Exception {
        hold = new java.util.concurrent.CountDownLatch(1);
        try {
            tab().domainField.setText("example.com");
            tab().checkButton.doClick(0);
            tab().rescanBox.setSelected(true);
            tab().checkButton.doClick(0);
            assertEquals(1, queue.jobs().size());
            assertTrue(tab().rescanBox.isSelected(), "the second click joined a job that does not rescan");
        } finally {
            hold.countDown();
        }
    }

    @Test
    void tickingPrivateEndsTheWaitOfARetryingJobAtOnce() throws Exception {
        hold = new java.util.concurrent.CountDownLatch(1);
        try {
            tab().domainField.setText("example.com");
            tab().checkButton.doClick(0);
            Job j = queue.jobs().get(0);
            pro.hirdman.radar.jobs.TestJobs.update(j, pro.hirdman.radar.jobs.JobState.RETRYING, "Server busy. Next try in 30 min.");
            java.util.concurrent.CompletableFuture<Void> waited = java.util.concurrent.CompletableFuture.runAsync(() -> {
                try {
                    pro.hirdman.radar.jobs.TestJobs.pause(j, java.time.Duration.ofSeconds(30));
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            });
            tab().projectBox.doClick(0);
            waited.get(5, java.util.concurrent.TimeUnit.SECONDS);
        } finally {
            hold.countDown();
        }
    }
}
