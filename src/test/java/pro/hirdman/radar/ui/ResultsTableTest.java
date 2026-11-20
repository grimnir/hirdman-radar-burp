package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.UIManager;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.Risk;

class ResultsTableTest {

    static final String D = "example.com";

    final ResultStore store = new ResultStore();
    final ResultsTableModel model = new ResultsTableModel(store, h -> true);
    final ResultsTable table = new ResultsTable(model);

    void checked(String host, int stealer, int work, int personal, long db, String severity) {
        List<Finding> f = severity == null ? List.of()
                : List.of(new Finding("k", severity, "tentative", "Leak", "", "", ""));
        store.apply(D, new Check(false, host, work, personal, db, 0, stealer, true, f), Instant.EPOCH);
    }

    void show() {
        model.setDomain(D);
    }

    JLabel cell(int viewRow, int col) {
        Component c = table.prepareRenderer(table.getCellRenderer(viewRow, col), viewRow, col);
        return (JLabel) c;
    }

    List<String> viewHosts() {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < table.getRowCount(); i++) {
            out.add((String) table.getValueAt(i, ResultsTableModel.HOST));
        }
        return out;
    }

    static boolean dark() {
        return RiskColors.dark(UIManager.getColor("Table.background"));
    }

    @Test
    void rendererIsNotHtml() {
        checked("a.example.com", 0, 0, 0, 0, null);
        show();
        for (int c = 0; c < table.getColumnCount(); c++) {
            JComponent r = cell(0, c);
            assertEquals(Boolean.TRUE, r.getClientProperty("html.disable"));
        }
        JLabel l = cell(0, ResultsTableModel.HOST);
        l.setText("<html><b>x</b></html>");
        assertNull(l.getClientProperty("html"));
    }

    @Test
    void riskWordAndNonZeroCountsAreColored() {
        checked("a.example.com", 3, 0, 5, 9, "high");
        checked("b.example.com", 0, 2, 0, 0, "medium");
        show();
        boolean dark = dark();
        assertEquals("High", cell(0, ResultsTableModel.RISK).getText());
        assertEquals(RiskColors.text(Risk.HIGH, dark), cell(0, ResultsTableModel.RISK).getForeground());
        assertEquals(RiskColors.text(Risk.HIGH, dark), cell(0, ResultsTableModel.STEALER).getForeground());
        assertEquals(table.getForeground(), cell(0, ResultsTableModel.WORK).getForeground());
        assertEquals(RiskColors.text(Risk.MEDIUM, dark), cell(0, ResultsTableModel.PERSONAL).getForeground());
        assertEquals(table.getForeground(), cell(0, ResultsTableModel.DB).getForeground());
        assertEquals(table.getForeground(), cell(0, ResultsTableModel.HOST).getForeground());
        assertEquals(RiskColors.text(Risk.MEDIUM, dark), cell(1, ResultsTableModel.RISK).getForeground());
        assertEquals(RiskColors.text(Risk.HIGH, dark), cell(1, ResultsTableModel.WORK).getForeground());
        assertEquals(table.getForeground(), cell(1, ResultsTableModel.STEALER).getForeground());
    }

    @Test
    void noneAndLowRiskStayNeutral() {
        checked("a.example.com", 0, 0, 0, 0, "low");
        checked("b.example.com", 0, 0, 0, 0, null);
        show();
        assertEquals("Low", cell(0, ResultsTableModel.RISK).getText());
        assertEquals(table.getForeground(), cell(0, ResultsTableModel.RISK).getForeground());
        assertEquals("", cell(1, ResultsTableModel.RISK).getText());
    }

    @Test
    void riskColorsFollowTheCellBackground() {
        checked("a.example.com", 3, 0, 5, 0, "high");
        show();
        for (int rgb : new int[] {0x383838, 0x333333, 0xEEEEEE, 0xF2F2F2}) {
            java.awt.Color bg = new java.awt.Color(rgb);
            table.setBackground(bg);
            boolean dark = RiskColors.dark(bg);
            JLabel risk = cell(0, ResultsTableModel.RISK);
            assertEquals(bg, risk.getBackground());
            assertEquals(RiskColors.text(Risk.HIGH, dark), risk.getForeground());
            assertTrue(RiskColors.contrast(risk.getForeground(), bg) >= RiskColors.MIN_CONTRAST, Integer.toHexString(rgb));
            assertEquals(RiskColors.text(Risk.MEDIUM, dark), cell(0, ResultsTableModel.PERSONAL).getForeground());
        }
        // A background no risk colour reads on: the theme's text colour.
        table.setBackground(new java.awt.Color(0x808080));
        assertEquals(table.getForeground(), cell(0, ResultsTableModel.RISK).getForeground());
    }

    @Test
    void countsAreRightAlignedWithThousandsSeparators() {
        checked("a.example.com", 10016, 1234, 0, 43778, null);
        store.apply(D, new Check(false, "b.example.com", 0, 0, 0, 0, 0, false, List.of()), Instant.EPOCH);
        show();
        assertEquals("10,016", cell(0, ResultsTableModel.STEALER).getText());
        assertEquals("1,234", cell(0, ResultsTableModel.WORK).getText());
        assertEquals("0", cell(0, ResultsTableModel.PERSONAL).getText());
        assertEquals("43,778", cell(0, ResultsTableModel.DB).getText());
        for (int c : new int[] {ResultsTableModel.STEALER, ResultsTableModel.WORK, ResultsTableModel.PERSONAL, ResultsTableModel.DB}) {
            assertEquals(javax.swing.SwingConstants.RIGHT, cell(0, c).getHorizontalAlignment());
            assertEquals(javax.swing.SwingConstants.RIGHT, cell(1, c).getHorizontalAlignment());
            assertEquals("", cell(1, c).getText());
        }
        assertEquals(javax.swing.SwingConstants.LEADING, cell(0, ResultsTableModel.HOST).getHorizontalAlignment());
        assertEquals(javax.swing.SwingConstants.LEADING, cell(0, ResultsTableModel.STATUS).getHorizontalAlignment());
        // Copies and exports keep plain numbers.
        assertEquals("10016", model.text(0, ResultsTableModel.STEALER));
        assertTrue(model.csv(new int[] {0}).contains(",10016,1234,0,43778,"));
    }

    @Test
    void selectedRowsUseTheSelectionColors() {
        checked("a.example.com", 3, 0, 0, 0, "high");
        show();
        table.setRowSelectionInterval(0, 0);
        assertEquals(table.getSelectionForeground(), cell(0, ResultsTableModel.RISK).getForeground());
    }

    @Test
    void countsSortAsNumbersWithBlanksFirst() {
        checked("a.example.com", 10, 0, 0, 0, null);
        checked("b.example.com", 9, 0, 0, 0, null);
        checked("c.example.com", 100, 0, 0, 0, null);
        store.apply(D, new Check(false, "d.example.com", 0, 0, 0, 0, 0, false, List.of()), Instant.EPOCH);
        show();
        table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(ResultsTableModel.STEALER, SortOrder.ASCENDING)));
        assertEquals(List.of("d.example.com", "b.example.com", "a.example.com", "c.example.com"), viewHosts());
        table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(ResultsTableModel.RISK, SortOrder.DESCENDING)));
        checked("e.example.com", 0, 0, 0, 0, "medium");
        model.refresh();
        assertEquals("e.example.com", viewHosts().get(0));
    }

    @Test
    void selectionIsByHostAndSurvivesRefresh() {
        checked("a.example.com", 0, 0, 0, 0, null);
        checked("b.example.com", 0, 0, 0, 0, null);
        show();
        table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(ResultsTableModel.HOST, SortOrder.DESCENDING)));
        table.setRowSelectionInterval(0, 0);
        assertEquals(List.of("b.example.com"), table.selected().stream().map(HostResult::host).toList());
        checked("0.example.com", 0, 0, 0, 0, "high");
        table.refreshKeepingSelection();
        assertEquals(List.of("b.example.com"), table.selected().stream().map(HostResult::host).toList());
        assertEquals(3, table.getRowCount());
    }

    @Test
    void anUnchangedRefreshKeepsTheSelectionAndItsLead() {
        checked("a.example.com", 0, 0, 0, 0, null);
        checked("b.example.com", 0, 0, 0, 0, null);
        checked("c.example.com", 0, 0, 0, 0, null);
        show();
        table.setRowSelectionInterval(0, 1);
        model.refresh();
        table.refreshKeepingSelection();
        assertEquals(List.of("a.example.com", "b.example.com"), table.selectedHosts());
        assertEquals(1, table.getSelectionModel().getLeadSelectionIndex());
        assertEquals(0, table.getSelectionModel().getAnchorSelectionIndex());
    }

    @Test
    void selectedModelRowsFollowTheView() {
        checked("a.example.com", 0, 0, 0, 0, null);
        checked("b.example.com", 0, 0, 0, 0, null);
        show();
        table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(ResultsTableModel.HOST, SortOrder.DESCENDING)));
        table.setRowSelectionInterval(0, 1);
        assertEquals("Host,Risk,Scope,Infostealer,Work,Personal,DB rec,Latest breach,Login page,Status\n"
                + "b.example.com,,in,0,0,0,0,,,Checked (nothing found)\na.example.com,,in,0,0,0,0,,,Checked (nothing found)\n", model.csv(table.selectedModelRows()));
    }

    @Test
    void theLatestBreachCellTipListsTheSources() {
        store.apply(D, new Check(false, "a.example.com", 1, 0, 0, 0, 0, true,
                List.of(new Finding("k", "high", "tentative", "Leak", "", "", "")),
                List.of(new pro.hirdman.radar.api.ServerEvent.BreachSource("Stealer Logs", "2024-03", 4))), Instant.EPOCH);
        show();
        java.awt.Rectangle latest = table.getCellRect(0, ResultsTableModel.LATEST, true);
        java.awt.Rectangle host = table.getCellRect(0, ResultsTableModel.HOST, true);
        java.awt.Rectangle status = table.getCellRect(0, ResultsTableModel.STATUS, true);
        assertEquals("Breach sources: Stealer Logs 4 (2024-03). Newer leaks may exist: not every record is dated.", table.getToolTipText(move(latest)));
        assertEquals(null, table.getToolTipText(move(host)));
        assertEquals("Checked 1970-01-01 00:00 UTC", table.getToolTipText(move(status)));
    }

    java.awt.event.MouseEvent move(java.awt.Rectangle r) {
        return new java.awt.event.MouseEvent(table, java.awt.event.MouseEvent.MOUSE_MOVED, 0, 0, r.x + 2, r.y + 2, 0, false);
    }

    @Test
    void columnsAreSizedToTheirContentAndHostTakesTheRest() {
        ResultsTable t = new ResultsTable(new ResultsTableModel(new ResultStore(), h -> true));
        java.awt.FontMetrics fm = t.getFontMetrics(t.getFont());
        javax.swing.table.TableColumnModel cols = t.getColumnModel();
        assertTrue(cols.getColumn(0).getPreferredWidth() >= fm.stringWidth("subdomain.example-domain.com"));
        assertTrue(cols.getColumn(ResultsTableModel.STATUS).getPreferredWidth() >= fm.stringWidth("Checked (nothing found)"));
        for (int c = 0; c < cols.getColumnCount(); c++) {
            // The name and the sort arrow fit.
            assertTrue(cols.getColumn(c).getPreferredWidth() >= fm.stringWidth(t.getColumnName(c)) + 16, t.getColumnName(c));
        }
        assertTrue(cols.getColumn(2).getPreferredWidth() < cols.getColumn(ResultsTableModel.STATUS).getPreferredWidth());
        assertEquals(Integer.MAX_VALUE, cols.getColumn(0).getMaxWidth());
        for (int c = 1; c < cols.getColumnCount(); c++) {
            assertTrue(cols.getColumn(c).getMaxWidth() < Integer.MAX_VALUE, t.getColumnName(c));
        }
    }

    @Test
    void headersExplainTheirColumns() {
        ResultsTable t = new ResultsTable(new ResultsTableModel(new ResultStore(), h -> true));
        javax.swing.table.JTableHeader h = t.getTableHeader();
        List<String> tips = new java.util.ArrayList<>();
        for (int c = 0; c < t.getColumnCount(); c++) {
            java.awt.Rectangle r = h.getHeaderRect(c);
            tips.add(h.getToolTipText(new java.awt.event.MouseEvent(h, java.awt.event.MouseEvent.MOUSE_MOVED, 0, 0,
                    r.x + r.width / 2, r.y + 2, 0, false)));
        }
        assertEquals(java.util.Arrays.asList(null,
                "Highest severity among the host's findings.",
                "In or out of Burp's target scope.",
                "Infostealer log records that mention the host.",
                "Breach records with work email addresses.",
                "Breach records with credentials for the host, whoever they belong to.",
                "Records in breached databases that mention the host, with an email or a URL.",
                "Newest known breach date among the 10 largest breach sources. Sources without a date, infostealer logs and"
                        + " database records are not dated, so newer leaks may exist. Hover a cell for the sources.",
                "A login page seen in Burp traffic for this host.",
                "Hover a cell for the time of the last check."), tips);
    }

    @Test
    void restoringABigSelectionFiresOneFinalEvent() {
        for (int i = 0; i < 1000; i++) {
            checked(String.format("h%04d.example.com", i), 0, 0, 0, 0, null);
        }
        show();
        table.setRowSelectionInterval(0, 999);
        table.removeRowSelectionInterval(500, 500);
        List<Boolean> events = new java.util.ArrayList<>();
        table.getSelectionModel().addListSelectionListener(e -> events.add(e.getValueIsAdjusting()));
        table.refreshKeepingSelection();
        assertEquals(999, table.getSelectedRowCount());
        assertTrue(!table.isRowSelected(500) && table.isRowSelected(499) && table.isRowSelected(501));
        // One event as the refresh clears the rows, one as the hosts are selected again; not one per row.
        assertTrue(events.stream().filter(adjusting -> !adjusting).count() <= 2, events.size() + " events");
    }

    @Test
    void headerNamesAreMeasuredWithTheHeaderFont() {
        ResultsTable t = new ResultsTable(new ResultsTableModel(new ResultStore(), h -> true));
        java.awt.Font big = new java.awt.Font(java.awt.Font.DIALOG, java.awt.Font.BOLD, 40);
        t.getTableHeader().setFont(big);
        java.awt.FontMetrics fm = t.getFontMetrics(big);
        for (int c = 1; c < t.getColumnCount(); c++) {
            assertTrue(t.getColumnModel().getColumn(c).getPreferredWidth() >= fm.stringWidth(t.getColumnName(c)) + 16,
                    t.getColumnName(c));
        }
    }
}
