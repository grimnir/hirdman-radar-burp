package pro.hirdman.radar.ui;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.swing.table.AbstractTableModel;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.export.ResultsExport;
import pro.hirdman.radar.jobs.StatusText;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.Risk;

/** Rows of one domain, filtered, highest risk first. Reads the store only in {@link #refresh()}. */
public final class ResultsTableModel extends AbstractTableModel {

    static final int HOST = 0;
    static final int RISK = 1;
    static final int SCOPE = 2;
    static final int STEALER = 3;
    static final int WORK = 4;
    static final int PERSONAL = 5;
    static final int DB = 6;
    static final int LATEST = 7;
    static final int LOGIN = 8;
    static final int STATUS = 9;
    private static final DateTimeFormatter AT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneOffset.UTC);
    private static final List<String> COLUMNS = List.of("Host", "Risk", "Scope", "Infostealer", "Work", "Host logins", "DB records",
            "Latest breach", "Login page", "Status");
    private static final Comparator<Row> ORDER = Comparator.comparing((Row r) -> r.result().risk()).reversed()
            .thenComparing(r -> r.result().host());

    private record Row(HostResult result, boolean inScope) {
    }

    private final ResultStore store;
    private final Predicate<String> inScope;
    private String domain;
    private ResultsFilter filter = ResultsFilter.ALL;
    private List<Row> rows = List.of();
    private String summary = "";
    private long leaksOutOfScope;
    private Optional<RestCheck> rest = Optional.empty();
    /** Burp's scope check is not free, and a refresh runs up to four times a second during a scan. */
    private final Map<String, Boolean> scopeCache = new HashMap<>();

    /** {@code inScope} takes a host name. */
    public ResultsTableModel(ResultStore store, Predicate<String> inScope) {
        this.store = store;
        this.inScope = inScope;
    }

    public String domain() {
        return domain;
    }

    public void setDomain(String d) {
        domain = d;
        scopeCache.clear();
        refresh();
    }

    public ResultsFilter filter() {
        return filter;
    }

    public void setFilter(ResultsFilter f) {
        filter = f;
        refresh();
    }

    public void refresh() {
        List<HostResult> all = domain == null ? List.of() : store.domain(domain);
        List<Row> scoped = all.stream().map(r -> new Row(r, inScope(r.host()))).toList();
        List<Row> next = scoped.stream().filter(r -> filter.keeps(r.result(), r.inScope())).sorted(ORDER).toList();
        leaksOutOfScope = scoped.stream().filter(r -> !r.inScope() && r.result().hasLeaks()).count();
        summary = summary(all);
        rest = RestCheck.of(domain, all);
        // An unchanged poll page must not reset the selection and the sort.
        if (!next.equals(rows)) {
            rows = next;
            fireTableDataChanged();
        }
    }

    private String summary(List<HostResult> all) {
        if (domain == null) {
            return "";
        }
        long leaks = all.stream().filter(HostResult::hasLeaks).count();
        long notCheckedYet = all.stream().filter(r -> r.status() == HostStatus.FOUND).count();
        long failed = all.stream().filter(r -> r.status() == HostStatus.NOT_CHECKED).count();
        return StatusText.summary(all.size(), leaks, notCheckedYet, failed);
    }

    /** Found subdomains of a checked domain, whatever the filter. */
    Optional<RestCheck> rest() {
        return rest;
    }

    /** Hosts of the domain with leaks outside Burp's scope, whatever the filter. */
    public long leaksOutOfScope() {
        return leaksOutOfScope;
    }

    /** Burp's scope for the host, asked once until {@link #forgetScope}. */
    public boolean inScope(String host) {
        return scopeCache.computeIfAbsent(host, inScope::test);
    }

    /** "120 hosts, 9 with leaks, 40 not checked yet, 3 failed" over the whole domain, whatever the filter. */
    public String summary() {
        return summary;
    }

    public HostResult rowAt(int row) {
        return rows.get(row).result();
    }

    /** Hosts of the domain the account check could not reach, filter aside. */
    public List<String> failed() {
        return domain == null ? List.of()
                : store.domain(domain).stream().filter(r -> r.status() == HostStatus.NOT_CHECKED).map(HostResult::host).toList();
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.size();
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS.get(column);
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return switch (column) {
            case RISK -> Risk.class;
            case HOST, SCOPE, LATEST, LOGIN, STATUS -> String.class;
            default -> Object.class;
        };
    }

    /** Counts are numbers once the host is checked, blank before: unknown is not zero. */
    @Override
    public Object getValueAt(int row, int column) {
        Row r = rows.get(row);
        HostResult h = r.result();
        boolean counted = h.status() == HostStatus.CHECKED || h.status() == HostStatus.CLEAN;
        return switch (column) {
            case HOST -> h.host();
            case RISK -> h.risk();
            case SCOPE -> r.inScope() ? "in" : "out";
            case STEALER -> counted ? h.stealer() : "";
            case WORK -> counted ? h.work() : "";
            case PERSONAL -> counted ? h.personal() : "";
            case DB -> counted ? h.dbRecords() : "";
            case LATEST -> Objects.toString(h.latestBreach(), "");
            case LOGIN -> h.login() == null ? "" : h.login().label();
            case STATUS -> h.status().label();
            default -> throw new IndexOutOfBoundsException(column);
        };
    }

    /** The cell as the table shows it. */
    public String text(int row, int column) {
        Object v = getValueAt(row, column);
        return v instanceof Risk risk ? risk.label() : String.valueOf(v);
    }

    /** CSV of the given model rows, column names first, quoted and defused as the CSV export does. */
    public String csv(int[] modelRows) {
        StringBuilder b = new StringBuilder(String.join(",", COLUMNS)).append('\n');
        for (int row : modelRows) {
            for (int c = 0; c < COLUMNS.size(); c++) {
                b.append(c == 0 ? "" : ",").append(ResultsExport.cell(text(row, c)));
            }
            b.append('\n');
        }
        return b.toString();
    }

    /** "Checked 2026-11-18 11:05 UTC" ("Last tried" after a failed check) for the Status cell's tooltip; null if never checked. */
    public String statusText(int row) {
        HostResult h = rows.get(row).result();
        if (h.checkedAt() == null || h.status() == HostStatus.FOUND) {
            return null;
        }
        return (h.status() == HostStatus.NOT_CHECKED ? "Last tried " : "Checked ") + AT.format(h.checkedAt()) + " UTC";
    }

    /**
     * "Breach sources: name count (date or no date); ..." and a note that newer leaks may exist, for the row's tooltip, or null
     * without sources. Never starts with "<html>".
     */
    public String sourcesText(int row) {
        List<BreachSource> sources = rows.get(row).result().sources();
        return sources.isEmpty() ? null : "Breach sources: " + sources.stream()
                .map(s -> s.name() + " " + s.count() + " (" + Objects.requireNonNullElse(s.date(), "no date") + ")")
                .collect(Collectors.joining("; ")) + ". Newer leaks may exist: not every record is dated.";
    }

    /** Burp's scope changed: the next refresh asks Burp again. */
    public void forgetScope() {
        scopeCache.clear();
    }
}
