package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.ResultStore;

class ExportActionsTest {

    final ResultStore store = new ResultStore();
    final Set<String> scope = new HashSet<>();
    final ResultsTableModel model = new ResultsTableModel(store, scope::contains);
    final TestLog log = new TestLog();
    final List<String> said = new ArrayList<>();
    final List<String> copied = new ArrayList<>();
    final ExportActions actions = new ExportActions(model, store, Options::defaults, scope::contains, Runnable::run, log,
            said::add, copied::add, JPanel::new, c -> { });

    void checked(String host, String severity) {
        List<Finding> f = severity == null ? List.of() : List.of(new Finding("k", severity, "tentative", "Leak", "", "", ""));
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 1, true, f), Instant.EPOCH);
    }

    void notChecked(String host) {
        store.apply("example.com", new Check(false, host, 0, 0, 0, 0, 0, false, List.of()), Instant.EPOCH);
    }

    JMenuItem item(String text) {
        for (Component c : actions.menu.getComponents()) {
            if (c instanceof JMenuItem i && i.getText().equals(text)) {
                return i;
            }
        }
        throw new AssertionError("no export item " + text);
    }

    @Test
    void theMenuOffersJsonCsvAndTheSummary() {
        assertEquals("Export \u25BE", actions.button.getText());
        assertEquals(java.awt.event.KeyEvent.VK_E, actions.button.getMnemonic());
        List<String> items = new ArrayList<>();
        for (Component c : actions.menu.getComponents()) {
            if (c instanceof JMenuItem i) {
                items.add(i.getText());
            }
        }
        assertEquals(List.of("JSON...", "CSV...", "Copy summary", "Import JSON..."), items);
    }

    @Test
    void exportWritesTheRowsShown(@TempDir Path dir) throws Exception {
        checked("a.example.com", "high");
        notChecked("b.example.com");
        model.setDomain("example.com");
        Path out = dir.resolve("r.json");
        List<String> asked = new ArrayList<>();
        actions.saveDialog = name -> {
            asked.add(name);
            return Optional.of(out);
        };
        item("JSON...").doClick(0);
        assertEquals(List.of("hirdman-radar-example.com.json"), asked);
        String json = Files.readString(out);
        assertTrue(json.contains("\"host\": \"a.example.com\""), json);
        assertTrue(json.contains("\"host\": \"b.example.com\""), json);
        assertTrue(json.contains("\"report_url\": \"https://scan.hirdman.pro/?domain=example.com\""), json);
        assertEquals(List.of("Hirdman Radar: exported 2 hosts to " + out), log.infos);
    }

    @Test
    void copySummaryCopiesTheWholeDomainWhateverTheFilter() {
        checked("a.example.com", "high");
        notChecked("b.example.com");
        model.setDomain("example.com");
        model.setFilter(ResultsFilter.FAILED);
        item("Copy summary").doClick(0);
        assertEquals(1, copied.size());
        assertTrue(copied.get(0).startsWith("## Hirdman Radar: example.com\n\n2 hosts, 1 with leaks, 1 failed."), copied.get(0));
        assertTrue(copied.get(0).contains("| a.example.com | High |"), copied.get(0));
        assertTrue(copied.get(0).contains("https://scan.hirdman.pro/?domain=example.com"), copied.get(0));
    }

    @Test
    void noSummaryWithoutADomainOnScreen() {
        item("Copy summary").doClick(0);
        assertEquals(List.of(), copied);
    }

    @Test
    void csvExportToAPlaceThatCannotBeWrittenIsLoggedAndSaid(@TempDir Path dir) throws Exception {
        checked("a.example.com", "high");
        model.setDomain("example.com");
        actions.saveDialog = name -> Optional.of(dir);
        item("CSV...").doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(List.of(ExportActions.EXPORT_FAILED), said);
        assertEquals(1, log.errors.size());
        assertTrue(log.errors.get(0).startsWith("Hirdman Radar: export to " + dir + " failed: "), log.errors.get(0));
        assertEquals(List.of(), log.causes, "a file that cannot be written is one line, without a stack");
    }

    @Test
    void anUnexpectedExportFailureKeepsItsStack(@TempDir Path dir) throws Exception {
        IllegalStateException broke = new IllegalStateException("scope broke");
        ExportActions failing = new ExportActions(model, store, Options::defaults, h -> {
            throw broke;
        }, Runnable::run, log, said::add, copied::add, JPanel::new, c -> { });
        checked("a.example.com", "high");
        model.setDomain("example.com");
        Path out = dir.resolve("r.csv");
        failing.saveDialog = name -> Optional.of(out);
        for (Component c : failing.menu.getComponents()) {
            if (c instanceof JMenuItem i && i.getText().equals("CSV...")) {
                i.doClick(0);
            }
        }
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(List.of("Hirdman Radar: export to " + out + " failed"), log.errors);
        assertEquals(List.of(broke), log.causes);
    }

    @Test
    void aCancelledExportWritesNothing() {
        checked("a.example.com", "high");
        model.setDomain("example.com");
        actions.saveDialog = name -> Optional.empty();
        item("CSV...").doClick(0);
        assertEquals(List.of(), log.infos);
        assertEquals(List.of(), log.errors);
    }

    /** An export of two checked hosts, written where an import will read it. */
    Path exported(Path dir) throws Exception {
        ResultStore other = new ResultStore();
        other.apply("example.com", new Check(false, "a.example.com", 0, 0, 0, 0, 7, true,
                List.of(new Finding("stealer_logs", "high", "tentative", "Leak", "", "", ""))), Instant.parse("2026-11-17T10:00:00Z"));
        other.apply("example.com", new Check(false, "c.example.com", 0, 0, 0, 0, 0, true, List.of()),
                Instant.parse("2026-11-17T10:00:00Z"));
        Path file = dir.resolve("hirdman-radar-example.com.json");
        Files.writeString(file, pro.hirdman.radar.export.ResultsExport.json("example.com", other.all(), h -> true, null, "0.2.0",
                Instant.parse("2026-11-17T11:00:00Z")));
        return file;
    }

    @Test
    void importMergesAnExportAndSaysWhatChanged(@TempDir Path dir) throws Exception {
        Path file = exported(dir);
        checked("a.example.com", "high");
        List<HostResult> checks = new ArrayList<>();
        store.addCheckListener(checks::add);
        actions.openDialog = () -> Optional.of(file);
        item("Import JSON...").doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(7, store.host("a.example.com").orElseThrow().stealer(), "the file's check is newer");
        assertEquals(HostStatus.CLEAN, store.host("c.example.com").orElseThrow().status());
        assertEquals(List.of("Imported hirdman-radar-example.com.json: 1 new host, 1 updated with a newer check. Nothing was sent"
                + " to the radar server."), said);
        assertEquals(List.of("Hirdman Radar: imported 2 hosts from " + file + ": 1 new, 1 updated, 0 kept"), log.infos);
        assertEquals(List.of(), checks);
        actions.openDialog = () -> Optional.of(file);
        item("Import JSON...").doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals("Imported hirdman-radar-example.com.json: 2 kept (the project's check is as new or newer). Nothing was sent to"
                + " the radar server.", said.get(1));
    }

    @Test
    void aFileThatIsNotAnExportIsRefusedAndNothingChanges(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("bad.json");
        Files.writeString(file, Files.readString(exported(dir)).replace("\"in_scope\"", "\"evil\""));
        actions.openDialog = () -> Optional.of(file);
        item("Import JSON...").doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(List.of(), store.all());
        assertEquals(List.of("Could not import bad.json: host 1 (a.example.com): unknown field \"evil\". Only a JSON export of"
                + " Hirdman Radar can be imported."), said);
        assertEquals(List.of("Hirdman Radar: import of " + file + " refused: host 1 (a.example.com): unknown field \"evil\""),
                log.errors);
    }

    @Test
    void aFileTooLargeIsNotRead(@TempDir Path dir) throws Exception {
        Path file = exported(dir);
        actions.maxImportBytes = 10;
        actions.openDialog = () -> Optional.of(file);
        item("Import JSON...").doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(List.of("Could not import hirdman-radar-example.com.json: the file is too large. Only a JSON export of Hirdman"
                + " Radar can be imported."), said);
        assertEquals(List.of(), store.all());
    }

    @Test
    void aFileThatCannotBeReadIsSaid(@TempDir Path dir) throws Exception {
        actions.openDialog = () -> Optional.of(dir.resolve("gone.json"));
        item("Import JSON...").doClick(0);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(List.of("Could not read gone.json. Details are in the extension's Errors tab."), said);
        assertEquals(1, log.errors.size());
    }

    @Test
    void aCancelledImportReadsNothing() {
        actions.openDialog = Optional::empty;
        item("Import JSON...").doClick(0);
        assertEquals(List.of(), said);
        assertEquals(List.of(), log.infos);
    }
}
