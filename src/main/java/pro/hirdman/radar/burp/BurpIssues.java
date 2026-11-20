package pro.hirdman.radar.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import pro.hirdman.radar.issues.IssueOptions;
import pro.hirdman.radar.issues.IssuePlanner;
import pro.hirdman.radar.issues.IssueSpec;
import pro.hirdman.radar.model.HostNames;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

/** Adds the issues of a checked host to Burp's site map, each name once per host. */
public final class BurpIssues {

    private final MontoyaApi api;
    private final Supplier<IssueOptions> options;
    /** Burp's issues under a base URL. */
    private final Function<String, List<AuditIssue>> existing;
    private final Function<IssueSpec, AuditIssue> toIssue;
    private final Set<String> reported = new HashSet<>();
    /** Base URLs whose issues in Burp were read this session. */
    private final Set<String> looked = new HashSet<>();

    public BurpIssues(MontoyaApi api, Supplier<IssueOptions> options) {
        this(api, options, baseUrl -> api.siteMap().issues(SiteMapFilter.prefixFilter(baseUrl)), BurpIssues::toIssue);
    }

    /** Burp's factories work only inside Burp, so tests pass their own. */
    BurpIssues(MontoyaApi api, Supplier<IssueOptions> options, Function<String, List<AuditIssue>> existing,
            Function<IssueSpec, AuditIssue> toIssue) {
        this.api = api;
        this.options = options;
        this.existing = existing;
        this.toIssue = toIssue;
    }

    /** Creates the missing issues of one host; returns how many were added. Never throws: Burp's refusals go to Errors. */
    public synchronized int report(HostResult r) {
        if (r.status() != HostStatus.CHECKED) {
            return 0;
        }
        String baseUrl = IssuePlanner.baseUrl(r.host());
        List<IssueSpec> specs;
        try {
            boolean inScope = api.scope().isInScope(baseUrl);
            specs = IssuePlanner.plan(r, inScope, options.get(), reported);
            // Nothing new against what this session knows: skip the site map lookup, which is the slow part.
            if (specs.isEmpty()) {
                return 0;
            }
            // Only this host's issues are read, once a session and again after reportAgain.
            if (!looked.contains(baseUrl)) {
                existing.apply(baseUrl).forEach(i -> key(i).ifPresent(reported::add));
                looked.add(baseUrl);
                specs = specs.stream().filter(s -> !reported.contains(s.key())).toList();
            }
        } catch (RuntimeException e) {
            api.logging().logToError("Hirdman Radar: issues for " + r.host() + " could not be created: " + e);
            return 0;
        }
        int added = 0;
        for (IssueSpec s : specs) {
            try {
                api.siteMap().add(toIssue.apply(s));
                reported.add(s.key());
                added++;
            } catch (RuntimeException e) {
                api.logging().logToError("Hirdman Radar: issue \"" + s.name() + "\" for " + r.host() + " could not be created: " + e);
            }
        }
        return added;
    }

    /** The key of an issue already in Burp, by name and host; an address without a host gives none. */
    private static Optional<String> key(AuditIssue i) {
        try {
            String host = URI.create(i.baseUrl()).getHost();
            return HostNames.normalize(host).map(h -> IssueSpec.key(i.name(), IssuePlanner.baseUrl(h)));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** {@link #report} for each row; returns how many issues were added. */
    public int reportAll(List<HostResult> rows) {
        return rows.stream().mapToInt(this::report).sum();
    }

    /** The row menu's action: goes by what Burp has now, so issues deleted there are created again. */
    public synchronized int reportAgain(List<HostResult> rows) {
        reported.clear();
        looked.clear();
        return reportAll(rows);
    }

    // The server's remediation is generic advice, so it goes under Burp's "Issue remediation", not the per-host field.
    private static AuditIssue toIssue(IssueSpec s) {
        AuditIssueSeverity severity = severity(s);
        return AuditIssue.auditIssue(s.name(), s.detail(), null, s.baseUrl(), severity, confidence(s), s.background(),
                s.remediation(), severity, List.of());
    }

    static AuditIssueSeverity severity(IssueSpec s) {
        return AuditIssueSeverity.valueOf(s.severity().toUpperCase(Locale.ROOT));
    }

    static AuditIssueConfidence confidence(IssueSpec s) {
        return AuditIssueConfidence.valueOf(s.confidence().toUpperCase(Locale.ROOT));
    }
}
