package pro.hirdman.radar.ui;

import java.awt.Component;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
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
import javax.swing.filechooser.FileNameExtensionFilter;
import pro.hirdman.radar.Version;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.export.ResultsExport;
import pro.hirdman.radar.export.ResultsImport;
import pro.hirdman.radar.export.ResultsSummary;
import pro.hirdman.radar.jobs.StatusText;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;

/**
 * The Export button and its menu: the rows shown as JSON or CSV, the whole domain as a Markdown summary, and an import of a
 * JSON export (offline review, sharing in a team) that sends nothing anywhere.
 */
final class ExportActions {

    static final String EXPORT_FAILED = "Could not save the export. Details are in the extension's Errors tab.";
    static final String IMPORT_ONLY = " Only a JSON export of Hirdman Radar can be imported.";

    /** The arrow says the button opens a menu. */
    final JButton button = new JButton("Export \u25BE");
    final JPopupMenu menu = new JPopupMenu();
    /** Asks where to save the export; tests replace it. */
    Function<String, Optional<Path>> saveDialog = this::chooseFile;
    /** Asks which export to import; tests replace it. */
    Supplier<Optional<Path>> openDialog = this::chooseImport;
    /** A larger file is not read; tests lower it. */
    long maxImportBytes = ResultsImport.MAX_CHARS;

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
        JMenuItem importJson = new JMenuItem("Import JSON...");
        importJson.addActionListener(e -> importJson());
        menu.addSeparator();
        menu.add(importJson);
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
        } catch (IOException | RuntimeException e) {
            log.error("Hirdman Radar: export to " + path + " failed: " + e);
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

    /** Reads the chosen export in the background and merges it; the file is checked whole before any row is added. */
    private void importJson() {
        openDialog.get().ifPresent(p -> background.execute(() -> read(p)));
    }

    private void read(Path path) {
        String name = String.valueOf(path.getFileName());
        String json;
        try {
            if (Files.size(path) > maxImportBytes) {
                refuse(path, name, "the file is too large");
                return;
            }
            json = Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            log.error("Hirdman Radar: import of " + path + " failed: " + e);
            SwingUtilities.invokeLater(() -> message.accept("Could not read " + name + ". Details are in the extension's Errors tab."));
            return;
        }
        List<HostResult> rows;
        try {
            rows = ResultsImport.parse(json, Instant.now());
        } catch (ResultsImport.Refused e) {
            refuse(path, name, e.getMessage());
            return;
        }
        ResultStore.Merged m = store.merge(rows);
        log.info("Hirdman Radar: imported " + StatusText.count(rows.size(), "host") + " from " + path + ": " + m.added() + " new, "
                + m.updated() + " updated, " + m.kept() + " kept" + (m.full() > 0 ? ", " + m.full() + " left out" : ""));
        SwingUtilities.invokeLater(() -> message.accept(importedText(name, m)));
    }

    private void refuse(Path path, String name, String why) {
        log.error("Hirdman Radar: import of " + path + " refused: " + why);
        SwingUtilities.invokeLater(() -> message.accept("Could not import " + name + ": " + why + "." + IMPORT_ONLY));
    }

    static String importedText(String name, ResultStore.Merged m) {
        List<String> parts = new ArrayList<>();
        if (m.added() > 0) {
            parts.add(StatusText.count(m.added(), "new host"));
        }
        if (m.updated() > 0) {
            parts.add(m.updated() + " updated with a newer check");
        }
        if (m.kept() > 0) {
            parts.add(m.kept() + " kept (the project's check is as new or newer)");
        }
        if (m.full() > 0) {
            parts.add(m.full() + " left out (the project holds as many hosts as it can)");
        }
        return "Imported " + name + ": " + (parts.isEmpty() ? "no hosts" : String.join(", ", parts))
                + ". Nothing was sent to the radar server.";
    }

    private Optional<Path> chooseImport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import results");
        chooser.setFileFilter(new FileNameExtensionFilter("Hirdman Radar JSON export", "json"));
        theme.accept(chooser);
        return chooser.showOpenDialog(parent.get()) == JFileChooser.APPROVE_OPTION ? Optional.of(chooser.getSelectedFile().toPath())
                : Optional.empty();
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
