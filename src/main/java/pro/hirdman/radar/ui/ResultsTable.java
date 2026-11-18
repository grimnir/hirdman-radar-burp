package pro.hirdman.radar.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.Risk;

/** The results table: sortable columns, risk colours, selection kept by host across refreshes. */
public final class ResultsTable extends JTable {

    /** Blank (unknown) counts sort below zero. */
    private static final Comparator<Object> COUNTS = Comparator.comparingLong(v -> v instanceof Number n ? n.longValue() : -1);

    /** Header tips by model column; Host needs none. */
    private static final List<String> HEADER_TIPS = Arrays.asList(null,
            "Highest severity among the host's findings.",
            "In or out of Burp's target scope.",
            "Infostealer log records that mention the host.",
            "Breach records with work email addresses.",
            "Breach records with credentials for the host, whoever they belong to.",
            "Records in breached databases that mention the host, with an email or a URL.",
            "Newest known breach date among the 10 largest breach sources. Sources without a date, infostealer logs and"
                    + " database records are not dated, so newer leaks may exist. Hover a cell for the sources.",
            "A login page seen in Burp traffic for this host.",
            "Hover a cell for the time of the last check.");
    /** The widest usual value of each model column. */
    private static final List<String> SAMPLES = List.of("subdomain.example-domain.com", "Medium", "out", "000000", "000000",
            "000000", "0000000", "2024-03-21", "FortiGate SSL VPN", "Checked (nothing found)");

    private final ResultsTableModel model;
    private final Renderer renderer = new Renderer();

    public ResultsTable(ResultsTableModel model) {
        super(model);
        this.model = model;
        TableRowSorter<ResultsTableModel> sorter = new TableRowSorter<>(model);
        for (int c : new int[] {ResultsTableModel.STEALER, ResultsTableModel.WORK, ResultsTableModel.PERSONAL, ResultsTableModel.DB}) {
            sorter.setComparator(c, COUNTS);
        }
        setRowSorter(sorter);
        setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        setFillsViewportHeight(true);
        // JTable answers tooltips only once registered.
        setToolTipText("");
        getTableHeader().addPropertyChangeListener("font", e -> fitColumns());
        fitColumns();
    }

    /** Burp's theme sets the font after construction; the widths follow it. */
    @Override
    public void setFont(Font font) {
        super.setFont(font);
        if (model != null) {
            fitColumns();
        }
    }

    /** Each column as wide as its usual value or its name; Host alone grows without a cap. */
    private void fitColumns() {
        FontMetrics cells = getFontMetrics(getFont());
        JTableHeader header = getTableHeader();
        // Themes often draw the header bold or larger than the cells.
        FontMetrics names = header == null || header.getFont() == null ? cells : header.getFontMetrics(header.getFont());
        for (int c = 0; c < getColumnCount(); c++) {
            TableColumn col = getColumnModel().getColumn(c);
            int m = col.getModelIndex();
            int width = Math.max(cells.stringWidth(SAMPLES.get(m)), names.stringWidth(model.getColumnName(m))) + 24;
            col.setPreferredWidth(width);
            if (m != ResultsTableModel.HOST) {
                col.setMaxWidth(width * 3);
            }
        }
    }

    @Override
    protected JTableHeader createDefaultTableHeader() {
        return new JTableHeader(columnModel) {
            @Override
            public String getToolTipText(MouseEvent e) {
                int column = columnAtPoint(e.getPoint());
                return column < 0 ? null : HEADER_TIPS.get(convertColumnIndexToModel(column));
            }
        };
    }

    /** Latest breach shows the breach sources, Status the time of the check. */
    @Override
    public String getToolTipText(MouseEvent e) {
        int row = rowAtPoint(e.getPoint());
        int column = columnAtPoint(e.getPoint());
        if (row < 0 || column < 0) {
            return null;
        }
        int modelRow = convertRowIndexToModel(row);
        return switch (convertColumnIndexToModel(column)) {
            case ResultsTableModel.LATEST -> model.sourcesText(modelRow);
            case ResultsTableModel.STATUS -> model.statusText(modelRow);
            default -> null;
        };
    }

    @Override
    public TableCellRenderer getCellRenderer(int row, int column) {
        return renderer;
    }

    public int[] selectedModelRows() {
        return Arrays.stream(getSelectedRows()).map(this::convertRowIndexToModel).toArray();
    }

    public List<HostResult> selected() {
        return Arrays.stream(selectedModelRows()).mapToObj(model::rowAt).toList();
    }

    public List<String> selectedHosts() {
        return selected().stream().map(HostResult::host).toList();
    }

    /** Hosts of the rows the filter shows. */
    public Set<String> hosts() {
        Set<String> out = new HashSet<>();
        for (int i = 0; i < model.getRowCount(); i++) {
            out.add(model.rowAt(i).host());
        }
        return out;
    }

    /** Re-reads the store and selects the same hosts again. */
    public void refreshKeepingSelection() {
        Set<String> keep = new HashSet<>(selectedHosts());
        model.refresh();
        select(keep);
    }

    /** Selects exactly these hosts and scrolls to the first of them. */
    public void selectHosts(Set<String> hosts) {
        clearSelection();
        select(hosts);
        int first = getSelectedRow();
        if (first >= 0) {
            scrollRectToVisible(getCellRect(first, 0, true));
        }
    }

    /** Adds runs of rows as single intervals inside one adjusting block, so listeners hear once, not per row. */
    private void select(Set<String> hosts) {
        ListSelectionModel sm = getSelectionModel();
        sm.setValueIsAdjusting(true);
        try {
            int rows = getRowCount();
            int start = -1;
            for (int i = 0; i <= rows; i++) {
                boolean in = i < rows && hosts.contains(model.rowAt(convertRowIndexToModel(i)).host());
                if (in && start < 0) {
                    start = i;
                } else if (!in && start >= 0) {
                    sm.addSelectionInterval(start, i - 1);
                    start = -1;
                }
            }
        } finally {
            sm.setValueIsAdjusting(false);
        }
    }

    /** Colour marks only the Risk word and non-zero Infostealer, Work (High) and Personal (Medium); zero stays neutral. */
    private static final class Renderer extends DefaultTableCellRenderer {

        Renderer() {
            putClientProperty("html.disable", Boolean.TRUE);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row,
                int column) {
            Object shown = value instanceof Risk r ? r.label() : value;
            super.getTableCellRendererComponent(table, shown, selected, focus, row, column);
            if (selected) {
                setForeground(table.getSelectionForeground());
            } else {
                Color c = RiskColors.text(colorRisk(value, table.convertColumnIndexToModel(column)),
                        RiskColors.dark(UIManager.getColor("Table.background")));
                setForeground(c != null ? c : table.getForeground());
            }
            return this;
        }

        private static Risk colorRisk(Object value, int column) {
            if (value instanceof Risk r) {
                return r;
            }
            boolean nonZero = value instanceof Number n && n.longValue() != 0;
            return switch (column) {
                case ResultsTableModel.STEALER, ResultsTableModel.WORK -> nonZero ? Risk.HIGH : Risk.NONE;
                case ResultsTableModel.PERSONAL -> nonZero ? Risk.MEDIUM : Risk.NONE;
                default -> Risk.NONE;
            };
        }
    }
}
