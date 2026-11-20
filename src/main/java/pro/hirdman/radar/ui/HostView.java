package pro.hirdman.radar.ui;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.export.ResultsExport;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.Risk;

/** One host's row as plain lines, for the Hirdman Radar tab in Burp's message editor. */
public final class HostView {

    private static final DateTimeFormatter AT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneOffset.UTC);
    /** Shown under a host with infostealer records; the link is tagged so visits from the editor can be told apart. */
    public static final String FULL_CHECK = "A full HIRDMAN check names the affected devices and whether sessions still work.";
    public static final String FULL_CHECK_URL = "https://hirdman.pro/?utm_source=burp&utm_medium=plugin&utm_content=editor";

    private HostView() {
    }

    /** Whether the full-check line belongs under this host. */
    public static boolean suggestsFullCheck(HostResult r) {
        return r.checked() && r.stealer() > 0;
    }

    public static List<String> lines(HostResult r) {
        return lines(r, Instant.now());
    }

    /** {@code now} dates a saved result the server gave instead of a new check. */
    public static List<String> lines(HostResult r, Instant now) {
        List<String> out = new ArrayList<>();
        switch (r.status()) {
            case FOUND -> out.add(r.host() + " was found as a subdomain of " + r.domain() + " and is not checked yet.");
            case NOT_CHECKED -> {
                out.add(r.host() + " could not be checked.");
                if (r.checkedAt() != null) {
                    out.add("Last tried " + AT.format(r.checkedAt()) + " UTC.");
                }
            }
            case CHECKED, CLEAN -> {
                out.add(r.host() + ": " + verdict(r));
                out.add("Infostealer logs: " + r.stealer() + ". Work records: " + r.work() + ". Personal records: " + r.personal()
                        + ". Database records: " + r.dbRecords() + ".");
                if (r.latestBreach() != null) {
                    out.add("Latest known breach: " + r.latestBreach() + ".");
                }
                r.findings().stream().sorted(Comparator.comparing((Finding f) -> Risk.ofSeverity(f.severity())).reversed())
                        .map(HostView::finding).forEach(out::add);
                out.add(checked(r, now) + ResultsExport.NOTE);
            }
        }
        if (r.login() != null) {
            out.add(1, "Login page seen in traffic: " + r.login().label() + " at " + r.login().path() + ".");
        }
        return out;
    }

    private static String checked(HostResult r, Instant now) {
        if (r.checkedAt() == null) {
            return "";
        }
        String at = AT.format(r.checkedAt()) + " UTC. ";
        return r.replayed() ? "Checked " + ago(Duration.between(r.checkedAt(), now)) + " (saved result), " + at : "Checked " + at;
    }

    /** "12 min ago", "3 h ago", "4 days ago". */
    static String ago(Duration d) {
        long minutes = Math.max(1, d.toMinutes());
        if (minutes < 60) {
            return minutes + " min ago";
        }
        long hours = d.toHours();
        return hours < 48 ? hours + " h ago" : d.toDays() + " days ago";
    }

    private static String verdict(HostResult r) {
        if (!r.hasLeaks()) {
            return "no leaks counted.";
        }
        Risk risk = r.risk();
        return risk == Risk.NONE ? "leaks counted." : risk.label() + " risk.";
    }

    private static String finding(Finding f) {
        Risk risk = Risk.ofSeverity(f.severity());
        return risk == Risk.NONE ? f.name() : risk.label() + ": " + f.name();
    }
}
