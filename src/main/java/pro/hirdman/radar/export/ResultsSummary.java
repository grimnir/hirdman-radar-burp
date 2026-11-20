package pro.hirdman.radar.export;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import pro.hirdman.radar.issues.IssuePlanner;
import pro.hirdman.radar.jobs.StatusText;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

/** A domain's results as a short Markdown block to paste into a report: totals, hosts with leaks, the notes. */
public final class ResultsSummary {

    static final String NOTES = ResultsExport.NOTE + " Partial check: about a third of a full HIRDMAN review. A full review shows"
            + " which accounts and devices are affected and whether the passwords still work.";
    /** A public service's host counts its users' logins, not the company's. */
    static final String HOST_LOGINS = "Host logins are credentials for a site on the host, whoever they belong to: for a public"
            + " service, its users.";
    private static final DateTimeFormatter DAY = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC);

    private ResultsSummary() {
    }

    /** Host names are checked names and the cells are numbers and dates, so nothing needs Markdown escaping. */
    public static String markdown(String domain, List<HostResult> rows, String site, Instant now) {
        long notCheckedYet = rows.stream().filter(r -> r.status() == HostStatus.FOUND).count();
        long failed = rows.stream().filter(r -> r.status() == HostStatus.NOT_CHECKED).count();
        List<HostResult> leaks = rows.stream().filter(HostResult::hasLeaks)
                .sorted(Comparator.comparing(HostResult::risk).reversed().thenComparing(HostResult::host)).toList();
        StringBuilder b = new StringBuilder("## Hirdman Radar: ").append(domain).append("\n\n")
                .append(StatusText.summary(rows.size(), leaks.size(), notCheckedYet, failed))
                .append(". Hirdman Radar summary, ").append(DAY.format(now)).append(" (UTC).\n\n");
        if (leaks.isEmpty()) {
            b.append("No leaks were counted for the checked hosts.\n\n");
        } else {
            b.append("| Host | Risk | Infostealer | Work | Host logins | DB records | Latest breach |\n|---|---|---|---|---|---|---|\n");
            for (HostResult r : leaks) {
                b.append("| ").append(r.host()).append(" | ").append(r.risk().label()).append(" | ").append(r.stealer())
                        .append(" | ").append(r.work()).append(" | ").append(r.personal()).append(" | ").append(r.dbRecords())
                        .append(" | ").append(Objects.toString(r.latestBreach(), "")).append(" |\n");
            }
            b.append('\n').append(HOST_LOGINS).append("\n\n");
        }
        b.append(NOTES).append('\n');
        IssuePlanner.siteUrl(domain, site).ifPresent(url ->
                b.append("\nLatest scan of ").append(domain).append(" and its subdomains: ").append(url).append('\n'));
        return b.toString();
    }
}
