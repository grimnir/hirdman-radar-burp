package pro.hirdman.radar.ui;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.export.ResultsExport;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.Risk;

/** One host's row as plain lines, for the Hirdman Radar tab in Burp's message editor. */
public final class HostView {

    private static final DateTimeFormatter AT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneOffset.UTC);

    private HostView() {
    }

    public static List<String> lines(HostResult r) {
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
                // Named as the table's columns.
                out.add("Infostealer: " + r.stealer() + ". Work: " + r.work() + ". Host logins: " + r.personal()
                        + ". DB records: " + r.dbRecords() + ".");
                if (r.latestBreach() != null) {
                    out.add("Latest known breach: " + r.latestBreach() + ".");
                }
                r.findings().stream().sorted(Comparator.comparing((Finding f) -> Risk.ofSeverity(f.severity())).reversed())
                        .map(HostView::finding).forEach(out::add);
                out.add(r.checkedAt() == null ? ResultsExport.NOTE : "Checked " + AT.format(r.checkedAt()) + " UTC. " + ResultsExport.NOTE);
            }
        }
        if (r.login() != null) {
            out.add(1, "Login page seen in traffic: " + r.login().label() + " at " + r.login().path() + ".");
        }
        return out;
    }

    public static String button(HostResult r) {
        return r.status() == HostStatus.FOUND ? "Check for leaks" : "Check again";
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
