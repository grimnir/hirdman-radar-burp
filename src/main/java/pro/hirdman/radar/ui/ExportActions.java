package pro.hirdman.radar.ui;

import java.awt.Component;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.SwingUtilities;
import pro.hirdman.radar.Version;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.export.ResultsExport;
import pro.hirdman.radar.export.ResultsSummary;
import pro.hirdman.radar.jobs.StatusText;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;

/** The Export button and its menu: the rows shown as JSON or CSV, the whole domain as a Markdown summary. */
final class ExportActions {

    static final String EXPORT_FAILED = "Could not save the export. Details are in the extension's Errors tab.";

    /** The arrow says the button opens a menu. */
    final JButton button = new JButton("Export \u25BE");
    final JPopupMenu menu = new JPopupMenu();
    /** Asks where to save the export; tests replace it. */
    Function<String, Optional<Path>> saveDialog = this::chooseFile;

    private final ResultsTableModel model;
    private final ResultStore store;
    private final Supplier<Options> options;
    private final Predicate<String> inScope;
    private final Executor background;
    private final TabLog log;
    private final Consumer<String> message;
    private final Consumer<String> clipboard;
    private final Supplier<Component> parent;
    private final Consumer<Component> theme;

    /**
     * {@code inScope} asks Burp's scope about a host; {@code message} and {@code clipboard} tell the user and copy text;
     * {@code parent} gives the window the file chooser opens over, {@code theme} styles it.
     */
    ExportActions(ResultsTableModel model, ResultStore store, Supplier<Options> options, Predicate<String> inScope,
            Executor background, TabLog log, Consumer<String> message, Consumer<String> clipboard, Supplier<Component> parent,
            Consumer<Component> theme) {
        this.model = model;
        this.store = store;
        this.options = options;
        this.inScope = inScope;
        this.background = background;
        this.log = log;
        this.message = message;
        this.clipboard = clipboard;
        this.parent = parent;
        this.theme = theme;
        buildMenu();
    }

    private void buildMenu() {
        JMenuItem json = new JMenuItem("JSON...");
        json.addActionListener(e -> export("json"));
        JMenuItem csv = new JMenuItem("CSV...");
        csv.addActionListener(e -> export("csv"));
        JMenuItem summary = new JMenuItem("Copy summary");
        summary.addActionListener(e -> copySummary());
        menu.add(json);
        menu.add(csv);
        menu.addSeparator();
        menu.add(summary);
        button.setMnemonic(KeyEvent.VK_E);
        button.addActionListener(e -> menu.show(button, 0, button.getHeight()));
    }

    /** The rows shown (domain and filter), written in the background. */
    private void export(String ext) {
        List<HostResult> rows = IntStream.range(0, model.getRowCount()).mapToObj(model::rowAt).toList();
        String domain = model.domain();
        Optional<Path> path = saveDialog.apply(ResultsExport.fileName(domain, ext));
        if (path.isEmpty()) {
            return;
        }
        String site = options.get().issueOptions().site();
        background.execute(() -> write(path.get(), ext, domain, rows, site));
    }

    private void write(Path path, String ext, String domain, List<HostResult> rows, String site) {
        try {
            String text = ext.equals("json")
                    ? ResultsExport.json(domain, rows, inScope, site, Version.current(), Instant.now())
                    : ResultsExport.csv(rows, inScope);
            Files.writeString(path, text, StandardCharsets.UTF_8);
            log.info("Hirdman Radar: exported " + StatusText.count(rows.size(), "host") + " to " + path);
        } catch (IOException e) {
            log.error("Hirdman Radar: export to " + path + " failed: " + e);
            SwingUtilities.invokeLater(() -> message.accept(EXPORT_FAILED));
        } catch (RuntimeException e) {
            log.error("Hirdman Radar: export to " + path + " failed", e);
            SwingUtilities.invokeLater(() -> message.accept(EXPORT_FAILED));
        }
    }

    /** The whole domain, whatever the filter, as Markdown for a report. */
    private void copySummary() {
        String domain = model.domain();
        if (domain != null) {
            clipboard.accept(ResultsSummary.markdown(domain, store.domain(domain), options.get().issueOptions().site(), Instant.now()));
        }
    }

    /** A save dialog that adds the extension and asks before replacing a file. */
    private Optional<Path> chooseFile(String name) {
        String ext = name.substring(name.lastIndexOf('.'));
        JFileChooser chooser = new JFileChooser() {
            @Override
            public void approveSelection() {
                File f = getSelectedFile();
                if (!f.getName().toLowerCase(Locale.ROOT).endsWith(ext)) {
                    f = new File(f.getParentFile(), f.getName() + ext);
                    setSelectedFile(f);
                }
                if (f.exists() && JOptionPane.showConfirmDialog(this, f.getName() + " already exists. Replace it?", "Export",
                        JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
                    return;
                }
                super.approveSelection();
            }
        };
        chooser.setDialogTitle("Export results");
        chooser.setSelectedFile(new File(name));
        theme.accept(chooser);
        return chooser.showSaveDialog(parent.get()) == JFileChooser.APPROVE_OPTION ? Optional.of(chooser.getSelectedFile().toPath())
                : Optional.empty();
    }
}
