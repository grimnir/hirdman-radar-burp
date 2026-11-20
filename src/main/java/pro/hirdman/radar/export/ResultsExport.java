package pro.hirdman.radar.export;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import pro.hirdman.radar.api.Json;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.issues.IssuePlanner;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.Risk;

/** Rows of the plugin tab as a JSON or CSV file: counts and finding names, as the table shows them. */
public final class ResultsExport {

    public static final String NOTE = "Counts only: no accounts, passwords, raw records or dumps.";
    static final String HEADER = "host,domain,status,risk,scope,stealer,work_accounts,host_logins,db_records,latest_breach,"
            + "checked_at,breach_sources,findings,login_page";
    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();

    private ResultsExport() {
    }

    /** Counts a check did not produce are null, never 0. */
    public static String json(String domain, List<HostResult> rows, Predicate<String> inScope, String site, String version,
            Instant now) {
        JsonObject root = new JsonObject();
        root.addProperty("tool", "Hirdman Radar");
        root.addProperty("version", version);
        root.addProperty("exported_at", now.toString());
        root.addProperty("domain", domain);
        root.addProperty("report_url", IssuePlanner.siteUrl(domain, site).orElse(null));
        root.addProperty("note", NOTE);
        JsonArray hosts = new JsonArray();
        for (HostResult r : rows) {
            boolean counted = counted(r);
            JsonObject h = new JsonObject();
            h.addProperty("host", r.host());
            h.addProperty("domain", r.domain());
            h.addProperty("status", r.status().label());
            h.addProperty("risk", r.risk() == Risk.NONE ? null : r.risk().label());
            h.addProperty("in_scope", inScope.test(r.host()));
            h.addProperty("stealer", counted ? Integer.valueOf(r.stealer()) : null);
            h.addProperty("work_accounts", counted ? Integer.valueOf(r.work()) : null);
            h.addProperty("personal_accounts", counted ? Integer.valueOf(r.personal()) : null);
            h.addProperty("db_records", counted ? Long.valueOf(r.dbRecords()) : null);
            h.addProperty("latest_breach", r.latestBreach());
            if (r.login() == null) {
                h.add("login_page", JsonNull.INSTANCE);
            } else {
                JsonObject login = new JsonObject();
                login.addProperty("type", r.login().label());
                login.addProperty("path", r.login().path());
                h.add("login_page", login);
            }
            if (counted) {
                JsonArray sources = new JsonArray();
                for (BreachSource s : r.sources()) {
                    JsonObject o = new JsonObject();
                    o.addProperty("name", s.name());
                    o.addProperty("date", s.date());
                    o.addProperty("count", s.count());
                    sources.add(o);
                }
                h.add("breach_sources", sources);
            } else {
                h.add("breach_sources", JsonNull.INSTANCE);
            }
            h.addProperty("checked_at", r.checkedAt() == null ? null : r.checkedAt().toString());
            JsonArray findings = new JsonArray();
            for (Finding f : r.findings()) {
                JsonObject o = new JsonObject();
                o.addProperty("name", Json.oneLine(f.name()));
                o.addProperty("severity", Json.oneLine(f.severity()));
                o.addProperty("confidence", Json.oneLine(f.confidence()));
                findings.add(o);
            }
            h.add("findings", findings);
            hosts.add(h);
        }
        root.add("hosts", hosts);
        return PRETTY.toJson(root) + "\n";
    }

    public static String csv(List<HostResult> rows, Predicate<String> inScope) {
        StringBuilder b = new StringBuilder(HEADER).append('\n');
        for (HostResult r : rows) {
            boolean counted = counted(r);
            String findings = r.findings().stream()
                    .map(f -> Objects.toString(Json.oneLine(f.name()), "") + " (" + Objects.toString(Json.oneLine(f.severity()), "") + ")")
                    .collect(Collectors.joining("; "));
            b.append(Stream.of(r.host(), r.domain(), r.status().label(), r.risk().label(), inScope.test(r.host()) ? "in" : "out",
                    counted ? String.valueOf(r.stealer()) : "", counted ? String.valueOf(r.work()) : "",
                    counted ? String.valueOf(r.personal()) : "", counted ? String.valueOf(r.dbRecords()) : "",
                    Objects.toString(r.latestBreach(), ""), r.checkedAt() == null ? "" : r.checkedAt().toString(),
                    sources(r), findings, r.login() == null ? "" : r.login().label() + " at " + r.login().path())
                    .map(ResultsExport::cell).collect(Collectors.joining(","))).append('\n');
        }
        return b.toString();
    }

    private static final Pattern NEEDS_QUOTES = Pattern.compile("[,\"\r\n]");

    /** RFC 4180 quoting; a leading = + - @ gets a quote mark so spreadsheets do not run it as a formula. */
    public static String cell(String v) {
        if (v == null || v.isEmpty()) {
            return "";
        }
        String s = "=+-@\t\r".indexOf(v.charAt(0)) >= 0 ? "'" + v : v;
        return NEEDS_QUOTES.matcher(s).find() ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }

    public static String fileName(String domain, String ext) {
        return "hirdman-radar-" + (domain == null ? "results" : domain) + "." + ext;
    }

    /** "name: count (date); ..." */
    private static String sources(HostResult r) {
        return r.sources().stream().map(s -> s.name() + ": " + s.count() + (s.date() == null ? "" : " (" + s.date() + ")"))
                .collect(Collectors.joining("; "));
    }

    private static boolean counted(HostResult r) {
        return r.status() == HostStatus.CHECKED || r.status() == HostStatus.CLEAN;
    }
}
