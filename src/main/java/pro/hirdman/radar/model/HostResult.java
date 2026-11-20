package pro.hirdman.radar.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;

/**
 * One host row. Counts: stealer = stealer_count, work = hc_corp_found, personal = hc_origin_found,
 * dbRecords = db_email_count + db_url_count. {@code checkedAt} is null until the host is checked;
 * {@code sources} are the breach_sources of the last check; {@code login} is a login page seen in traffic, or null;
 * {@code replayed}: the server gave a saved result, checked at {@code checkedAt}, not a check just then.
 */
public record HostResult(String host, String domain, HostStatus status, int stealer, int work, int personal,
        long dbRecords, List<Finding> findings, Instant checkedAt, List<BreachSource> sources, LoginPage login,
        boolean replayed) {

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
        return new HostResult(host, domain, status, stealer, work, personal, dbRecords, findings, checkedAt, sources, page, replayed);
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

    /** Checked successfully within {@link #FRESH_FOR}; a failed or never-run check is never fresh. */
    public boolean freshAt(Instant now) {
        return checked() && checkedAt != null && checkedAt.isAfter(now.minus(FRESH_FOR));
    }
}
