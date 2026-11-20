package pro.hirdman.radar.ui;

import static pro.hirdman.radar.ui.PlainText.label;
import static pro.hirdman.radar.ui.PlainText.plain;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import java.util.stream.Collectors;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import pro.hirdman.radar.Version;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.config.ProjectSwitch;
import pro.hirdman.radar.issues.IssuePlanner;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.StatusText;
import pro.hirdman.radar.model.HostNames;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;

/** The Hirdman Radar suite tab: domain field, Jobs strip, results table, server line and footer, in Burp's own theme. */
public final class RadarTab extends JPanel {

    static final String EMPTY = "No results yet. Enter a domain above, or right-click a host in Target, Proxy or Repeater "
            + "and choose Extensions > Hirdman Radar.";
    static final String SITE = "https://hirdman.pro";
    static final String WORKING = "Results appear here as hosts are checked.";
    static final String RESCAN_TIP = "Scan the domain again instead of using the saved scan or the checks of the last 24 h. "
            + "Without a key, a domain can be rescanned once an hour. Unticks itself once the job is queued.";
    static final String NOT_A_DOMAIN = "Enter a domain name like example.com. IP addresses cannot be checked.";
    static final String PRIVATE_HINT = "This project is private: nothing is sent to the radar server. Untick \"Private project\" "
            + "at the bottom of this tab to check a domain.";
    private static final String[] REMOVE_BUTTONS = {"Remove", "Cancel"};
    private static final Duration PERIOD = Duration.ofMillis(250);
    private static final String TABLE_CARD = "table";
    private static final String EMPTY_CARD = "empty";
    static final String NOTICE_SEEN = "noticeSeen";
    private static final List<String> NOTICE = List.of(
            "Hirdman Radar sends the domains and host names you pick to the radar server and gets back counts only. "
                    + "Nothing else from your project is sent.",
            "New in-scope hosts from traffic are sent only if you turn that on in Settings > Extensions > Hirdman Radar.",
            "For a project whose host names must not leave Burp, tick \"Private project\" at the bottom of this tab.");
    private static final String PRIVATE_TIP = "For engagements where host names must not leave Burp. While ticked, this project "
            + "sends nothing to scan.hirdman.pro: no checks, no subdomain search, no traffic checks. Results already here stay. "
            + "Other projects are not affected.";

    private final MontoyaApi api;
    private final ResultStore store;
    private final JobQueue queue;
    private final Supplier<Options> options;
    private final ProjectSwitch projectSwitch;
    private final ToIntFunction<List<HostResult>> report;
    private final Function<List<String>, String> addToSiteMap;
    private final Executor background;
    private final TabLog log;
    private final UpdateCoalescer updates = new UpdateCoalescer(PERIOD, this::flush);
    private final Registration scopeWatch;
    final Timer timer;

    final JPanel noticePanel = new JPanel(new BorderLayout(12, 0));
    final List<JLabel> noticeLines = NOTICE.stream().map(PlainText::label).toList();
    final JButton gotItButton = new JButton("Got it");
    final JTextField domainField = new JTextField(24);
    final JButton findButton = new JButton("Find subdomains");
    final JButton checkButton = new JButton("Check for leaks");
    final JCheckBox rescanBox = new JCheckBox("Rescan");
    final JLabel domainHint = plain(new JLabel());
    final ScopeCheckButton scopeCheck;
    final JobsPanel jobsPanel;
    final JScrollPane jobsScroll;
    final JComboBox<String> domainBox = new JComboBox<>();
    final JLabel summaryLabel = plain(new JLabel());
    final JLabel scopeHint = plain(new JLabel());
    final JPanel restPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    final JLabel restLabel = plain(new JLabel());
    final JButton restButton = new JButton("Check them");
    final JComboBox<ResultsFilter> filterBox = new JComboBox<>(ResultsFilter.values());
    final ResultsTableModel model;
    final ResultsTable table;
    final JLabel emptyLabel = label(EMPTY, SwingConstants.CENTER);
    final ServerStatus server;
    final JCheckBox projectBox = new JCheckBox("Private project: send nothing to the radar");
    final JLabel projectHelp = label("(?)");
    final JButton link = new Link("hirdman.pro");
    final JLabel versionLabel = new Note("Hirdman Radar " + Version.current());
    final JPopupMenu rowMenu = new JPopupMenu();
    final ExportActions export;
    /** Puts text on the system clipboard; tests replace it. */
    Consumer<String> clipboard = this::copy;
    /** The window dialogs open over: Burp's main window, not this tab (BApp Store rule). */
    final Supplier<Component> dialogParent;
    /** Tells the user something that needs no answer; tests replace it. */
    Consumer<String> message;
    /** Asks before a big host check; tests replace it. */
    SendConfirm confirm;
    /** Remove / Cancel with Cancel as the default: a removed check costs a server check to get back. */
    Predicate<String> confirmRemove;
    /** Whether the tab is on screen; tests replace it. */
    BooleanSupplier shown = this::isShowing;
    private final AtomicBoolean scopeChanged = new AtomicBoolean();

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel cards = new JPanel(cardLayout);
    private final JMenuItem checkSelectedItem = new JMenuItem("Check selected hosts");
    private final JMenuItem checkAgainItem = new JMenuItem("Check again");
    private final JMenuItem recheckItem = new JMenuItem("Re-check failed");
    private final JMenuItem scopeItem = new JMenuItem("Add selected to scope");
    private final JMenuItem siteMapItem = new JMenuItem("Add selected to site map");
    private final JMenuItem issuesItem = new JMenuItem("Create issues for selected hosts");
    private final JMenuItem copyHostsItem = new JMenuItem("Copy hosts");
    private final JMenuItem copyCsvItem = new JMenuItem("Copy as CSV");
    private final JMenuItem removeItem = new JMenuItem("Remove from results");
    private boolean updatingDomains;

    /**
     * {@code report} turns the selected rows into Burp issues and returns how many it created; {@code scopeHosts} lists
     * the in-scope hosts of the site map and runs in the background.
     */
    public RadarTab(MontoyaApi api, ResultStore store, JobQueue queue, MetaGate gate, Supplier<Options> options,
            ProjectSwitch projectSwitch, Supplier<Radar> radar, ToIntFunction<List<HostResult>> report,
            Function<List<String>, String> addToSiteMap, Supplier<List<String>> scopeHosts, Supplier<Component> dialogParent) {
        this(api, store, queue, gate, options, projectSwitch, radar, report, addToSiteMap, scopeHosts, dialogParent,
                RadarTab::inBackground);
    }

    RadarTab(MontoyaApi api, ResultStore store, JobQueue queue, MetaGate gate, Supplier<Options> options,
            ProjectSwitch projectSwitch, Supplier<Radar> radar, ToIntFunction<List<HostResult>> report,
            Function<List<String>, String> addToSiteMap, Supplier<List<String>> scopeHosts, Supplier<Component> dialogParent,
            Executor background) {
        super(new BorderLayout(0, 6));
        this.api = api;
        this.dialogParent = dialogParent;
        this.message = m -> JOptionPane.showMessageDialog(dialogParent.get(), m, "Hirdman Radar", JOptionPane.INFORMATION_MESSAGE);
        this.confirm = SendConfirm.dialog(dialogParent);
        this.confirmRemove = q -> JOptionPane.showOptionDialog(dialogParent.get(), q, "Hirdman Radar", JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE, null, REMOVE_BUTTONS, REMOVE_BUTTONS[1]) == 0;
        this.store = store;
        this.queue = queue;
        this.options = options;
        this.projectSwitch = projectSwitch;
        this.report = report;
        this.addToSiteMap = addToSiteMap;
        this.background = background;
        this.log = TabLog.of(m -> api.logging().raiseInfoEvent(m), m -> api.logging().logToError(m),
                (m, e) -> api.logging().logToError(m, e));
        Predicate<String> inScope = h -> api.scope().isInScope(IssuePlanner.baseUrl(h));
        this.model = new ResultsTableModel(store, inScope);
        this.table = new ResultsTable(model);
        this.jobsPanel = new JobsPanel(queue);
        this.jobsScroll = new JobsScroll(jobsPanel);
        // The parts call the tab's dialogs and clipboard through these lambdas, so tests can replace them later.
        Consumer<String> tell = m -> message.accept(m);
        SendConfirm ask = q -> confirm.ask(q);
        this.server = new ServerStatus(options, gate, radar, background, log);
        this.export = new ExportActions(model, store, options, inScope, background, log, tell, t -> clipboard.accept(t),
                dialogParent, api.userInterface()::applyThemeToComponent);
        this.scopeCheck = new ScopeCheckButton(options, store, queue, scopeHosts, server::limitsNow, background, log, tell, ask);

        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(north(), BorderLayout.NORTH);
        add(results(), BorderLayout.CENTER);
        add(south(), BorderLayout.SOUTH);
        buildRowMenu();

        store.addListener(updates::mark);
        scopeWatch = api.scope().registerScopeChangeHandler(e -> {
            scopeChanged.set(true);
            updates.mark();
        });
        timer = new Timer(updates.periodMillis(), e -> tick());
        flush();
        api.userInterface().applyThemeToComponent(this);
        api.userInterface().applyThemeToComponent(rowMenu);
        api.userInterface().applyThemeToComponent(export.menu);
    }

    private JPanel north() {
        JLabel domainLabel = new JLabel("Domain");
        domainLabel.setLabelFor(domainField);
        rescanBox.setToolTipText(RESCAN_TIP);
        findButton.setMnemonic(KeyEvent.VK_F);
        checkButton.setMnemonic(KeyEvent.VK_C);
        domainField.addActionListener(e -> submit(JobKind.FIND_AND_CHECK));
        checkButton.addActionListener(e -> submit(JobKind.FIND_AND_CHECK));
        findButton.addActionListener(e -> submit(JobKind.FIND_SUBDOMAINS));
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row.add(domainLabel);
        row.add(domainField);
        row.add(findButton);
        row.add(checkButton);
        row.add(rescanBox);
        row.add(Box.createHorizontalStrut(12));
        row.add(scopeCheck.button);
        domainHint.setVisible(false);
        domainHint.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 0));
        JPanel form = new JPanel(new BorderLayout(0, 4));
        form.add(row, BorderLayout.CENTER);
        form.add(domainHint, BorderLayout.SOUTH);
        jobsScroll.setBorder(BorderFactory.createTitledBorder("Jobs"));
        JPanel top = new JPanel(new BorderLayout(0, 6));
        top.add(notice(), BorderLayout.NORTH);
        top.add(form, BorderLayout.SOUTH);
        JPanel north = new JPanel(new BorderLayout(0, 6));
        north.add(top, BorderLayout.NORTH);
        north.add(jobsScroll, BorderLayout.CENTER);
        return north;
    }

    /** What leaves Burp, shown once per user until Got it. */
    private JPanel notice() {
        JPanel lines = new JPanel();
        lines.setLayout(new BoxLayout(lines, BoxLayout.Y_AXIS));
        noticeLines.forEach(lines::add);
        JPanel button = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        button.add(gotItButton);
        noticePanel.add(lines, BorderLayout.CENTER);
        noticePanel.add(button, BorderLayout.EAST);
        noticePanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));
        noticePanel.setVisible(!Boolean.TRUE.equals(api.persistence().preferences().getBoolean(NOTICE_SEEN)));
        gotItButton.addActionListener(e -> {
            api.persistence().preferences().setBoolean(NOTICE_SEEN, true);
            noticePanel.setVisible(false);
        });
        return noticePanel;
    }

    private JPanel results() {
        domainBox.addActionListener(e -> {
            String d = (String) domainBox.getSelectedItem();
            if (!updatingDomains && d != null && !d.equals(model.domain())) {
                model.setDomain(d);
            }
        });
        filterBox.addActionListener(e -> model.setFilter((ResultsFilter) filterBox.getSelectedItem()));
        model.addTableModelListener(e -> {
            summaryLabel.setText(model.summary());
            showScopeHint();
            showRest();
        });
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        header.add(new JLabel("Results"));
        header.add(domainBox);
        header.add(summaryLabel);
        JLabel show = new JLabel("Show");
        show.setLabelFor(filterBox);
        header.add(show);
        header.add(filterBox);
        header.add(export.button);
        cards.add(new JScrollPane(table), TABLE_CARD);
        cards.add(emptyLabel, EMPTY_CARD);
        JPanel p = new JPanel(new BorderLayout(0, 4));
        p.add(header, BorderLayout.NORTH);
        p.add(cards, BorderLayout.CENTER);
        scopeHint.setVisible(false);
        restButton.addActionListener(e -> checkRest());
        restPanel.add(restLabel);
        restPanel.add(restButton);
        restPanel.setVisible(false);
        JPanel hints = new JPanel(new BorderLayout());
        hints.add(restPanel, BorderLayout.NORTH);
        hints.add(scopeHint, BorderLayout.SOUTH);
        p.add(hints, BorderLayout.SOUTH);
        return p;
    }

    /** Shown while the domain on screen was scanned and some of its subdomains are still only found. */
    private void showRest() {
        Optional<RestCheck> rest = model.rest();
        restLabel.setText(rest.map(RestCheck::line).orElse(""));
        restPanel.setVisible(rest.isPresent());
    }

    /** A few hosts go at once; more wait for a question with this hour's allowance, asked afresh in the background. */
    private void checkRest() {
        Optional<RestCheck> rest = model.rest();
        if (rest.isEmpty()) {
            return;
        }
        if (sayIfPrivate()) {
            return;
        }
        Options o = options.get();
        RestCheck r = rest.get();
        if (r.hosts().size() <= SendConfirm.QUIET_HOSTS) {
            queue.submit(JobKind.CHECK_HOSTS, null, r.hosts(), false);
            return;
        }
        restButton.setEnabled(false);
        background.execute(() -> {
            Meta.Limits limits = server.limitsNow(o);
            SwingUtilities.invokeLater(() -> {
                restButton.setEnabled(true);
                if (confirm.ask(r.question(limits))) {
                    queue.submit(JobKind.CHECK_HOSTS, null, r.hosts(), false);
                }
            });
        });
    }

    /** Shown while automatic issues skip out-of-scope hosts and some of them have leaks. */
    private void showScopeHint() {
        Options o = options.get();
        long out = o.autoIssues() && !o.includeOutOfScope() ? model.leaksOutOfScope() : 0;
        scopeHint.setText(out == 0 ? "" : outOfScope(out));
        scopeHint.setVisible(out > 0);
    }

    static String outOfScope(long n) {
        String head = n == 1
                ? "1 host with leaks is out of Burp's scope, so it gets no issues. Add it"
                : StatusText.count(n, "host") + " with leaks are out of Burp's scope, so they get no issues. Add them";
        return head + " to scope, or tick \"Include out-of-scope hosts\" in Settings > Extensions > Hirdman Radar.";
    }

    private JPanel south() {
        link.addActionListener(e -> background.execute(this::openSite));
        // Burp takes one settings panel per extension, so this per-project switch sits here, kept in the project file.
        projectBox.setSelected(projectSwitch.off());
        projectBox.setToolTipText(PRIVATE_TIP);
        projectHelp.setToolTipText(PRIVATE_TIP);
        projectBox.addActionListener(e -> {
            projectSwitch.set(projectBox.isSelected());
            if (projectBox.isSelected()) {
                // A job waiting out a limit stops now, not when its wait ends.
                queue.jobs().forEach(queue::retryNow);
            }
            server.check();
        });
        JPanel south = new JPanel(new BorderLayout(0, 4));
        south.add(serverRow(), BorderLayout.NORTH);
        south.add(footer(), BorderLayout.SOUTH);
        return south;
    }

    /** The server line on the left, the project switch on the right. */
    private JPanel serverRow() {
        // Try again first: a long reason is cut at the right edge, never the button; the tip has it whole.
        JPanel line = new JPanel(new BorderLayout(6, 0));
        line.add(server.tryAgainButton, BorderLayout.WEST);
        line.add(server.label, BorderLayout.CENTER);
        JPanel row = new JPanel(new BorderLayout(12, 0));
        row.add(line, BorderLayout.CENTER);
        JPanel project = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        project.add(projectBox);
        project.add(projectHelp);
        row.add(project, BorderLayout.EAST);
        return row;
    }

    /** The footer note on the left, the version and the site link on the right. */
    private JPanel footer() {
        JPanel footer = new JPanel(new BorderLayout(12, 0));
        footer.add(server.footerLabel, BorderLayout.CENTER);
        JPanel corner = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        corner.add(versionLabel);
        corner.add(link);
        footer.add(corner, BorderLayout.EAST);
        return footer;
    }

    private void buildRowMenu() {
        checkSelectedItem.addActionListener(e -> checkHosts(table.selectedHosts()));
        checkAgainItem.addActionListener(e -> checkAgain(table.selectedHosts()));
        recheckItem.addActionListener(e -> checkHosts(model.failed()));
        scopeItem.addActionListener(e -> addToScope());
        siteMapItem.addActionListener(e -> addSelectedToSiteMap(table.selectedHosts()));
        issuesItem.addActionListener(e -> createIssues(table.selected()));
        KeyStroke copyKey = KeyStroke.getKeyStroke(KeyEvent.VK_C, shortcutMask());
        KeyStroke deleteKey = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);
        copyHostsItem.addActionListener(e -> copyHosts());
        copyHostsItem.setAccelerator(copyKey);
        copyCsvItem.addActionListener(e -> clipboard.accept(model.csv(table.selectedModelRows())));
        removeItem.addActionListener(e -> removeSelected());
        removeItem.setAccelerator(deleteKey);
        // The table's own Ctrl+C would copy every cell; this one copies host names like the menu.
        bind("radar.copyHosts", this::copyHosts, copyKey);
        bind("radar.remove", this::removeSelected, deleteKey, KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0));
        rowMenu.add(checkSelectedItem);
        rowMenu.add(checkAgainItem);
        rowMenu.add(recheckItem);
        rowMenu.addSeparator();
        rowMenu.add(scopeItem);
        rowMenu.add(siteMapItem);
        rowMenu.add(issuesItem);
        rowMenu.addSeparator();
        rowMenu.add(copyHostsItem);
        rowMenu.add(copyCsvItem);
        rowMenu.addSeparator();
        rowMenu.add(removeItem);
        rowMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                prepareRowMenu();
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
            }
        });
        table.setComponentPopupMenu(rowMenu);
        // A right-click on an unselected row acts on that row, as elsewhere in Burp.
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                if (SwingUtilities.isRightMouseButton(e) && row >= 0 && !table.isRowSelected(row)) {
                    table.setRowSelectionInterval(row, row);
                    prepareRowMenu();
                }
            }
        });
    }

    void prepareRowMenu() {
        boolean any = table.getSelectedRowCount() > 0;
        for (JMenuItem i : List.of(checkSelectedItem, checkAgainItem, scopeItem, siteMapItem, issuesItem, copyHostsItem, copyCsvItem, removeItem)) {
            i.setEnabled(any);
        }
        recheckItem.setEnabled(!model.failed().isEmpty());
    }

    /** Shows the domain of the first host with a row, every row if the filter hides one, and selects its hosts. */
    public void reveal(List<String> hosts) {
        List<HostResult> rows = hosts.stream().map(store::host).flatMap(Optional::stream).toList();
        if (rows.isEmpty()) {
            return;
        }
        String domain = rows.get(0).domain();
        Set<String> wanted = rows.stream().filter(r -> r.domain().equals(domain)).map(HostResult::host)
                .collect(Collectors.toSet());
        model.setDomain(domain);
        refreshDomains(store.domains());
        if (!table.hosts().containsAll(wanted)) {
            filterBox.setSelectedItem(ResultsFilter.ALL);
        }
        table.selectHosts(wanted);
    }

    private void submit(JobKind kind) {
        String raw = domainField.getText().trim();
        Optional<String> d = HostNames.domainInput(raw);
        // A line under the field, not a dialog: a typo is not worth a window.
        String hint = d.isEmpty() && !raw.isEmpty() ? NOT_A_DOMAIN
                : d.isPresent() && options.get().offForProject() ? PRIVATE_HINT : "";
        domainHint.setText(hint);
        domainHint.setVisible(!hint.isEmpty());
        if (d.isEmpty() || !hint.isEmpty()) {
            domainField.requestFocusInWindow();
            return;
        }
        domainField.setText(d.get());
        // A click that joins an active job without a rescan leaves the box ticked: nothing was rescanned.
        if (queue.submit(kind, d.get(), List.of(), rescanBox.isSelected()).rescan()) {
            rescanBox.setSelected(false);
        }
        model.setDomain(d.get());
        refreshDomains(store.domains());
        updates.mark();
    }

    /** Cmd on macOS, Ctrl elsewhere; Ctrl without a screen. */
    static int shortcutMask() {
        try {
            return Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        } catch (HeadlessException e) {
            return InputEvent.CTRL_DOWN_MASK;
        }
    }

    private void bind(String name, Runnable action, KeyStroke... keys) {
        for (KeyStroke k : keys) {
            table.getInputMap(JComponent.WHEN_FOCUSED).put(k, name);
        }
        table.getActionMap().put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    private void copyHosts() {
        List<String> hosts = table.selectedHosts();
        if (!hosts.isEmpty()) {
            clipboard.accept(String.join("\n", hosts));
        }
    }

    private void removeSelected() {
        List<String> hosts = table.selectedHosts();
        if (hosts.size() > 1 && !confirmRemove.test("Remove " + StatusText.count(hosts.size(), "host") + " from the results?")) {
            return;
        }
        store.remove(hosts);
    }

    private void checkHosts(List<String> hosts) {
        if (!sayIfPrivate() && confirm.allows(queue.toSend(hosts).size())) {
            queue.submit(JobKind.CHECK_HOSTS, null, hosts, false);
        }
    }

    private void checkAgain(List<String> hosts) {
        if (!sayIfPrivate() && confirm.allows(hosts.size())) {
            queue.checkAgain(hosts);
        }
    }

    /** A job in a private project would fail at once, so the user is told instead. */
    private boolean sayIfPrivate() {
        if (!options.get().offForProject()) {
            return false;
        }
        message.accept(ServerLine.OFF_FOR_PROJECT.text());
        return true;
    }

    private void addToScope() {
        table.selectedHosts().forEach(h -> api.scope().includeInScope(IssuePlanner.baseUrl(h)));
        model.forgetScope();
        table.refreshKeepingSelection();
    }

    private void addSelectedToSiteMap(List<String> hosts) {
        background.execute(() -> log.info(addToSiteMap.apply(hosts)));
    }

    private void createIssues(List<HostResult> rows) {
        long out = options.get().includeOutOfScope() ? 0
                : rows.stream().filter(r -> r.hasLeaks() && !model.inScope(r.host())).count();
        background.execute(() -> {
            int created = report.applyAsInt(rows);
            log.info("Hirdman Radar: created " + StatusText.count(created, "issue") + " for "
                    + StatusText.count(rows.size(), "host") + (out == 0 ? "" : ". " + outOfScope(out)));
        });
    }

    private void copy(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (HeadlessException | IllegalStateException e) {
            log.error("Hirdman Radar: the clipboard is not available: " + e);
        }
    }

    /** Called by the job queue from any thread. */
    public void jobsChanged() {
        updates.mark();
    }

    /** Extension unload: stops the timer and the scope watch. */
    public void close() {
        timer.stop();
        scopeWatch.deregister();
    }

    @Override
    public void addNotify() {
        super.addNotify();
        timer.start();
    }

    @Override
    public void removeNotify() {
        timer.stop();
        super.removeNotify();
    }

    /** A hidden tab does no work: changes wait for the first tick after it is shown again. */
    void tick() {
        if (shown.getAsBoolean()) {
            updates.tick();
            server.watch();
        }
    }

    /** Applies every change since the last flush; runs on the EDT. */
    void flush() {
        if (scopeChanged.getAndSet(false)) {
            model.forgetScope();
        }
        List<Job> jobs = queue.jobs();
        jobsPanel.show(jobs);
        jobsScroll.setVisible(jobsPanel.hasJobs());
        emptyLabel.setText(emptyText(jobs));
        List<String> stored = store.domains();
        refreshDomains(stored);
        table.refreshKeepingSelection();
        cardLayout.show(cards, stored.isEmpty() ? EMPTY_CARD : TABLE_CARD);
        revalidate();
    }

    /** What the empty table says: results are on the way while a job is active. */
    static String emptyText(List<Job> jobs) {
        return jobs.stream().anyMatch(j -> !j.state().finished()) ? WORKING : EMPTY;
    }

    /** The chooser lists the stored domains, plus the one on screen while its first rows are on the way. */
    private void refreshDomains(List<String> stored) {
        List<String> domains = new ArrayList<>(stored);
        String current = model.domain();
        if (current == null && !domains.isEmpty()) {
            current = domains.get(0);
            model.setDomain(current);
        }
        if (current != null && !domains.contains(current)) {
            domains.add(current);
        }
        List<String> shown = new ArrayList<>();
        for (int i = 0; i < domainBox.getItemCount(); i++) {
            shown.add(domainBox.getItemAt(i));
        }
        updatingDomains = true;
        try {
            if (!shown.equals(domains)) {
                domainBox.setModel(new DefaultComboBoxModel<>(domains.toArray(new String[0])));
            }
            domainBox.setSelectedItem(current);
        } finally {
            updatingDomains = false;
        }
    }

    private void openSite() {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(SITE));
                return;
            }
        } catch (IOException | RuntimeException e) {
            log.error("Hirdman Radar: cannot open " + SITE + ": " + e);
            return;
        }
        log.error("Hirdman Radar: no browser to open here. The site is " + SITE);
    }

    private static void inBackground(Runnable r) {
        Thread t = new Thread(r, "hirdman-radar-ui");
        t.setDaemon(true);
        t.start();
    }

    /** The Jobs strip grows with its rows up to about four of them, then scrolls. */
    private static final class JobsScroll extends JScrollPane {

        JobsScroll(JobsPanel view) {
            super(view);
        }

        @Override
        public Dimension getPreferredSize() {
            Dimension d = super.getPreferredSize();
            return new Dimension(d.width, Math.min(d.height, getFontMetrics(getFont()).getHeight() * 9));
        }
    }

    /** A focusable text link in the theme's secondary colour, or its main one when the secondary reads poorly. */
    private static final class Link extends JButton {

        Link(String text) {
            super(text);
            putClientProperty("html.disable", Boolean.TRUE);
            setBorderPainted(false);
            setContentAreaFilled(false);
            setMargin(new Insets(0, 0, 0, 0));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setToolTipText(SITE);
        }

        @Override
        public void updateUI() {
            super.updateUI();
            secondary(this);
        }
    }

    /** The plugin version beside the site link, small and in the same colour. */
    private static final class Note extends JLabel {

        Note(String text) {
            super(text);
            putClientProperty("html.disable", Boolean.TRUE);
            setToolTipText("Plugin version. Quote it when you report a problem.");
        }

        @Override
        public void updateUI() {
            super.updateUI();
            secondary(this);
        }
    }

    /** One size smaller, in the theme's secondary colour or its main one when the secondary reads poorly. */
    private static void secondary(JComponent c) {
        c.setForeground(RiskColors.readable(UIManager.getColor("Label.disabledForeground"), UIManager.getColor("Label.foreground"),
                UIManager.getColor("Panel.background")));
        Font f = UIManager.getFont("Label.font");
        if (f != null) {
            c.setFont(f.deriveFont(f.getSize2D() - 1f));
        }
    }
}
