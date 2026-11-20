package pro.hirdman.radar.model;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;

/**
 * One host row. Counts: stealer = stealer_count, work = hc_corp_found, personal = hc_origin_found,
 * dbRecords = db_email_count + db_url_count. {@code checkedAt} is null until the host is checked;
 * {@code sources} are the breach_sources of the last check; {@code login} is a login page seen in traffic, or null;
 * {@code replayed}: the server gave a saved result, checked at {@code checkedAt}, not a check just then;
 * {@code previous}: the counts of the counted check before, or null when not known (rows saved by older versions).
 */
public record HostResult(String host, String domain, HostStatus status, int stealer, int work, int personal,
        long dbRecords, List<Finding> findings, Instant checkedAt, List<BreachSource> sources, LoginPage login,
        boolean replayed, Previous previous) {

    /** Counts of an earlier check. A null {@code checkedAt} means there was none: every count is then 0. */
    public record Previous(int stealer, int work, int personal, long dbRecords, Instant checkedAt) {

        /** The host had no counted check before. */
        public static final Previous FIRST = new Previous(0, 0, 0, 0, null);

        public Previous {
            boolean known = checkedAt != null;
            stealer = known ? Math.max(0, stealer) : 0;
            work = known ? Math.max(0, work) : 0;
            personal = known ? Math.max(0, personal) : 0;
            dbRecords = known ? Math.max(0, dbRecords) : 0;
        }

        static Previous of(HostResult r) {
            return new Previous(r.stealer(), r.work(), r.personal(), r.dbRecords(), r.checkedAt());
        }

        public boolean first() {
            return checkedAt == null;
        }
    }

    /** The server sends the top 10; a project file is held to the same. */
    static final int MAX_SOURCES = 10;
    /** The contract has four kinds; more would flood the issues and the project file. */
    static final int MAX_FINDINGS = 10;
    /** A successful check this recent is not sent again unless asked. */
    public static final Duration FRESH_FOR = Duration.ofHours(24);

    public HostResult {
        findings = findings == null ? List.of() : findings.stream().filter(Objects::nonNull).limit(MAX_FINDINGS).toList();
        sources = sources == null ? List.of() : sources.stream()
                .filter(s -> s != null && s.name() != null && !s.name().isEmpty()).limit(MAX_SOURCES).toList();
    }

    public HostResult(String host, String domain, HostStatus status, int stealer, int work, int personal, long dbRecords,
            List<Finding> findings, Instant checkedAt, List<BreachSource> sources, LoginPage login, boolean replayed) {
        this(host, domain, status, stealer, work, personal, dbRecords, findings, checkedAt, sources, login, replayed, null);
    }

    public HostResult(String host, String domain, HostStatus status, int stealer, int work, int personal, long dbRecords,
            List<Finding> findings, Instant checkedAt, List<BreachSource> sources, LoginPage login) {
        this(host, domain, status, stealer, work, personal, dbRecords, findings, checkedAt, sources, login, false);
    }

    public HostResult(String host, String domain, HostStatus status, int stealer, int work, int personal, long dbRecords,
            List<Finding> findings, Instant checkedAt, List<BreachSource> sources) {
        this(host, domain, status, stealer, work, personal, dbRecords, findings, checkedAt, sources, null);
    }

    public HostResult(String host, String domain, HostStatus status, int stealer, int work, int personal, long dbRecords,
            List<Finding> findings, Instant checkedAt) {
        this(host, domain, status, stealer, work, personal, dbRecords, findings, checkedAt, List.of());
    }

    public HostResult withLogin(LoginPage page) {
        return new HostResult(host, domain, status, stealer, work, personal, dbRecords, findings, checkedAt, sources, page, replayed,
                previous);
    }

    public HostResult withPrevious(Previous p) {
        return new HostResult(host, domain, status, stealer, work, personal, dbRecords, findings, checkedAt, sources, login, replayed,
                p);
    }

    /** A row without a successful check: no counts, no findings. */
    static HostResult withoutCounts(String host, String domain, HostStatus status, Instant checkedAt) {
        return new HostResult(host, domain, status, 0, 0, 0, 0, List.of(), checkedAt);
    }

    /** The newest breach date among the sources (YYYY, YYYY-MM or YYYY-MM-DD), or null. */
    public String latestBreach() {
        return sources.stream().map(BreachSource::date).filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null);
    }

    public Risk risk() {
        return Risk.of(findings);
    }

    public boolean hasLeaks() {
        return !findings.isEmpty();
    }

    /** The last check went through, with or without leaks. */
    public boolean checked() {
        return status == HostStatus.CHECKED || status == HostStatus.CLEAN;
    }

    /** "Infostealer +12, Host logins -1" against the previous check, "new" for a first check that counted leaks; "" otherwise. */
    public String changeText() {
        if (!checked() || previous == null) {
            return "";
        }
        if (previous.first()) {
            return newSinceLastCheck() ? "new" : "";
        }
        List<String> parts = new ArrayList<>();
        delta(parts, "Infostealer", stealer - (long) previous.stealer());
        delta(parts, "Work", work - (long) previous.work());
        delta(parts, "Host logins", personal - (long) previous.personal());
        delta(parts, "DB records", dbRecords - previous.dbRecords());
        return String.join(", ", parts);
    }

    private static void delta(List<String> parts, String name, long d) {
        if (d != 0) {
            parts.add(name + " " + (d > 0 ? "+" : "") + d);
        }
    }

    /** A counted check with a count above the previous one; on a first check, any count above zero. */
    public boolean newSinceLastCheck() {
        return checked() && previous != null && (stealer > previous.stealer() || work > previous.work()
                || personal > previous.personal() || dbRecords > previous.dbRecords());
    }

    /** Checked successfully within {@link #FRESH_FOR}; a failed or never-run check is never fresh. */
    public boolean freshAt(Instant now) {
        return checked() && checkedAt != null && checkedAt.isAfter(now.minus(FRESH_FOR));
    }
}
