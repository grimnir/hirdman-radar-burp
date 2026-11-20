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
        assertEquals("Export", actions.button.getText());
        List<String> items = new ArrayList<>();
        for (Component c : actions.menu.getComponents()) {
            if (c instanceof JMenuItem i) {
                items.add(i.getText());
            }
        }
        assertEquals(List.of("JSON...", "CSV...", "Copy summary"), items);
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
}
