package pro.hirdman.radar.issues;

import java.net.URI;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostNames;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.LoginPage;
import pro.hirdman.radar.model.Risk;

/** Which Burp issues a host row gets. The auto option is the caller's: manual creation uses the same plan. */
public final class IssuePlanner {

    /** Finding kinds of the server contract, with the plugin's own name and severity; other kinds get no issue. */
    private record Kind(String name, Risk risk) {
    }

    // Names as the server wrote them so far: Burp has no update, a new name would add a second issue for the same host.
    private static final Map<String, Kind> KINDS = Map.of(
            "stealer_logs", new Kind("Host found in infostealer logs", Risk.HIGH),
            "work_accounts", new Kind("Work email addresses found in breaches", Risk.HIGH),
            "personal_accounts", new Kind("Credentials for host found in breaches", Risk.MEDIUM),
            "breached_db_records", new Kind("Host found in breached databases", Risk.LOW));
    /** What ConnectionSettings produces; anything else gets no link, so nothing odd reaches the issue HTML. */
    private static final DateTimeFormatter DAY = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC);
    private static final Pattern SITE = Pattern.compile("https?://[a-z0-9.\\-\\[\\]:]+");

    private IssuePlanner() {
    }

    /** Names say where the issue came from, in Burp's Issues and in its reports. */
    static final String PREFIX = "Hirdman Radar: ";
    static final String LOGIN = "Login page on a host with leaked records";
    private static final String LOGIN_REMEDIATION = "<p>Check that this login asks for a second factor and is open only to those"
            + " who need it.</p>";

    public static String baseUrl(String host) {
        return "https://" + host + "/";
    }

    /** Issues for a checked host, one per finding, minus filtered ones and those already in {@code alreadyReported}. */
    public static List<IssueSpec> plan(HostResult r, boolean inScope, IssueOptions o, Set<String> alreadyReported) {
        if (r.status() != HostStatus.CHECKED || !inScope && !o.includeOutOfScope()) {
            return List.of();
        }
        String baseUrl = baseUrl(r.host());
        String server = siteHost(o.site());
        String link = null;
        Set<String> seen = new HashSet<>();
        List<IssueSpec> out = new ArrayList<>();
        for (Finding f : r.findings()) {
            Kind kind = f.kind() == null ? null : KINDS.get(f.kind());
            if (kind == null || kind.risk().compareTo(o.lowest()) < 0) {
                continue;
            }
            // Checked before the HTML is cleaned: a scope pass meets mostly issues that already exist.
            String key = IssueSpec.key(PREFIX + kind.name(), baseUrl);
            if (alreadyReported.contains(key) || !seen.add(key)) {
                continue;
            }
            if (link == null) {
                link = sourcesLine(r) + checkedLine(r, o.site());
            }
            // Every finding is tentative: the records are not verified.
            out.add(new IssueSpec(PREFIX + kind.name(), IssueHtml.clean(f.detail(), server) + link,
                    IssueHtml.clean(f.remediation(), server), baseUrl, severity(kind.risk()), "tentative",
                    IssueHtml.clean(f.background(), server)));
        }
        LoginPage login = r.login();
        if (login != null && Risk.LOW.compareTo(o.lowest()) >= 0 && !alreadyReported.contains(IssueSpec.key(PREFIX + LOGIN, baseUrl))) {
            out.add(new IssueSpec(PREFIX + LOGIN, loginDetail(r, login) + sourcesLine(r) + checkedLine(r, o.site()),
                    LOGIN_REMEDIATION, baseUrl, "low", "tentative", ""));
        }
        return out;
    }

    /** Cautious on purpose: the page only looks like a login, and nobody checked whether a leaked password works. */
    private static String loginDetail(HostResult r, LoginPage login) {
        // Records, not accounts: one account can appear in several records.
        List<String> parts = new ArrayList<>();
        if (r.stealer() > 0) {
            parts.add(r.stealer() + " in infostealer logs");
        }
        if (r.work() > 0) {
            parts.add(r.work() == 1 ? "1 with a work email address" : r.work() + " with work email addresses");
        }
        if (r.personal() > 0) {
            parts.add(r.personal() + " with credentials for the host");
        }
        if (r.dbRecords() > 0) {
            parts.add(r.dbRecords() + " in breached databases");
        }
        return "<p>Burp traffic shows what looks like a login page on this host: <b>" + IssueHtml.text(login.label()) + "</b> at <b>"
                + IssueHtml.text(login.path()) + "</b>."
                + (parts.isEmpty() ? "" : " The leak archive has records for this host: " + String.join(", ", parts) + ".")
                + "</p><p>Leaked passwords are often tried on login pages like this one."
                + " Hirdman Radar counts records only and did not check whether any password works here.</p>";
    }

    /** The domain's page on the radar site: the site shows the latest scan from its cache, or runs one. */
    public static Optional<String> siteUrl(String domain, String site) {
        Optional<String> d = domain == null ? Optional.empty() : HostNames.normalize(domain);
        if (site == null || !SITE.matcher(site).matches() || d.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(site + "/?domain=" + d.get());
    }

    /** The host of a site that passes {@link #siteUrl}, or null. */
    static String siteHost(String site) {
        if (site == null || !SITE.matcher(site).matches()) {
            return null;
        }
        try {
            return URI.create(site).getHost();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** The breaches the host's records come from, as plain text; empty without sources. */
    static String sourcesLine(HostResult r) {
        return r.sources().isEmpty() ? "" : "<p>Breach sources for this host: " + r.sources().stream()
                .map(s -> IssueHtml.text(s.name()) + ": " + s.count() + (s.date() == null ? "" : " (" + s.date() + ")"))
                .collect(Collectors.joining("; ")) + ".</p>";
    }

    /** The plugin's line after the server detail: when the host was checked and the domain's page on the site. */
    static String checkedLine(HostResult r, String site) {
        List<String> parts = new ArrayList<>();
        if (r.checkedAt() != null) {
            parts.add("Checked by Hirdman Radar on " + DAY.format(r.checkedAt()) + " (UTC).");
        }
        siteUrl(r.domain(), site).ifPresent(url -> parts.add("Latest scan of " + HostNames.normalize(r.domain()).orElseThrow()
                + " and its subdomains: <a href=\"" + url + "\">" + url + "</a>. Its counts can differ from this issue."));
        return parts.isEmpty() ? "" : "<p>" + String.join(" ", parts) + "</p>";
    }

    private static String severity(Risk risk) {
        return switch (risk) {
            case HIGH -> "high";
            case MEDIUM -> "medium";
            case LOW -> "low";
            case NONE -> "information";
        };
    }
}
