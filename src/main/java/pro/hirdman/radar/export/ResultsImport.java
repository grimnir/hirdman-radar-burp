package pro.hirdman.radar.export;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.io.StringReader;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import pro.hirdman.radar.api.Json;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostNames;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostResult.Previous;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.LoginPage;
import pro.hirdman.radar.model.Risk;

/**
 * Reads a JSON file of {@link ResultsExport} back into rows. The file can come from anyone, so it is all or nothing: any
 * field the export does not write, or writes otherwise, refuses the whole file. Server texts are not in the export, so
 * imported findings have none.
 */
public final class ResultsImport {

    /** Far above any export: one host takes well under a kilobyte. */
    public static final int MAX_CHARS = 32 * 1024 * 1024;
    /** As many rows as a project loads. */
    static final int MAX_HOSTS = 100_000;
    /** The export writes one-line texts of at most 300 characters. */
    static final int MAX_TEXT = 1_000;
    private static final int MAX_FIELD_SHOWN = 40;

    private static final Set<String> TOP = Set.of("tool", "version", "exported_at", "domain", "report_url", "note", "hosts");
    private static final Set<String> HOST = Set.of("host", "domain", "status", "risk", "in_scope", "stealer", "work_accounts",
            "personal_accounts", "db_records", "latest_breach", "login_page", "breach_sources", "checked_at", "findings", "previous");
    private static final Set<String> COUNTS = Set.of("stealer", "work_accounts", "personal_accounts", "db_records");
    private static final Set<String> FINDING = Set.of("name", "severity", "confidence", "kind");
    private static final Set<String> SOURCE = Set.of("name", "date", "count");
    private static final Set<String> LOGIN = Set.of("type", "path");
    private static final Set<String> PREVIOUS = Set.of("stealer", "work_accounts", "personal_accounts", "db_records", "checked_at");
    private static final Set<String> RISKS = Set.of(Risk.LOW.label(), Risk.MEDIUM.label(), Risk.HIGH.label());

    /** Why a file was not imported, in words for the user. */
    public static final class Refused extends Exception {
        Refused(String message) {
            super(message);
        }
    }

    private ResultsImport() {
    }

    /** The rows of an export, in file order; {@code now} bounds check times. */
    public static List<HostResult> parse(String json, Instant now) throws Refused {
        return parse(json, now, MAX_HOSTS);
    }

    static List<HostResult> parse(String json, Instant now, int maxHosts) throws Refused {
        if (json != null && json.length() > MAX_CHARS) {
            throw new Refused("the file is too large");
        }
        if (json == null || json.isBlank()) {
            throw new Refused("the file is empty");
        }
        JsonElement parsed = read(json);
        if (parsed == null) {
            throw new Refused("the file is not JSON");
        }
        if (!(parsed instanceof JsonObject root) || !(root.get("tool") instanceof JsonPrimitive tool)
                || !"Hirdman Radar".equals(tool.getAsString())) {
            throw new Refused("the file is not a Hirdman Radar JSON export");
        }
        known(root, TOP, "");
        if (!(root.get("hosts") instanceof JsonArray hosts)) {
            throw new Refused("the file has no host list");
        }
        for (String name : List.of("version", "exported_at", "domain", "report_url", "note")) {
            text(root, name, "");
        }
        if (hosts.size() > maxHosts) {
            throw new Refused("the file has more than " + maxHosts + " hosts");
        }
        List<HostResult> rows = new ArrayList<>(hosts.size());
        for (int i = 0; i < hosts.size(); i++) {
            rows.add(host(hosts.get(i), i + 1, now));
        }
        return rows;
    }

    /** Strict JSON, one value and nothing after it; null when the text is not that. */
    private static JsonElement read(String json) {
        try {
            JsonReader reader = new JsonReader(new StringReader(json));
            reader.setStrictness(Strictness.STRICT);
            JsonElement root = JsonParser.parseReader(reader);
            return reader.peek() == JsonToken.END_DOCUMENT ? root : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static HostResult host(JsonElement el, int n, Instant now) throws Refused {
        if (!(el instanceof JsonObject o)) {
            throw new Refused("host " + n + " is not an object");
        }
        String rawHost = text(o, "host", "host " + n + ": ");
        Optional<String> host = HostNames.normalize(rawHost);
        if (host.isEmpty()) {
            throw new Refused("host " + n + ": host " + quote(rawHost) + " is not a host name");
        }
        String at = "host " + n + " (" + host.get() + "): ";
        known(o, HOST, at);
        String rawDomain = text(o, "domain", at);
        Optional<String> domain = HostNames.normalize(rawDomain);
        if (domain.isEmpty()) {
            throw new Refused(at + "domain " + quote(rawDomain) + " is not a host name");
        }
        if (!HostNames.within(host.get(), domain.get())) {
            throw new Refused(at + "host is not under its domain " + domain.get());
        }
        HostStatus status = status(text(o, "status", at), at);
        String risk = text(o, "risk", at);
        if (risk != null && !RISKS.contains(risk)) {
            throw new Refused(at + "risk is not a risk");
        }
        if (present(o, "in_scope") && !(o.get("in_scope") instanceof JsonPrimitive p && p.isBoolean())) {
            throw new Refused(at + "in_scope is not true or false");
        }
        text(o, "latest_breach", at);
        Instant checkedAt = time(o, "checked_at", at, now);
        LoginPage login = login(o, at);
        List<Finding> findings = findings(o, at);
        List<BreachSource> sources = sources(o, at);
        Previous previous = previous(o, at, now);

        if (status == HostStatus.FOUND || status == HostStatus.NOT_CHECKED) {
            String what = status == HostStatus.FOUND ? "a host not checked yet" : "a failed check";
            if (COUNTS.stream().anyMatch(c -> present(o, c))) {
                throw new Refused(at + what + " has no counts");
            }
            if (!findings.isEmpty()) {
                throw new Refused(at + what + " has no findings");
            }
            if (!sources.isEmpty()) {
                throw new Refused(at + what + " has no breach sources");
            }
            if (status == HostStatus.FOUND && (checkedAt != null || previous != null)) {
                throw new Refused(at + what + " has no check time and no previous check");
            }
            return new HostResult(host.get(), domain.get(), status, 0, 0, 0, 0, List.of(), checkedAt, List.of(), login, false,
                    previous);
        }
        if (status == HostStatus.CHECKED && findings.isEmpty()) {
            throw new Refused(at + "status says leaks found but the host has no findings");
        }
        if (status == HostStatus.CLEAN && !findings.isEmpty()) {
            throw new Refused(at + "status says nothing found but the host has findings");
        }
        return new HostResult(host.get(), domain.get(), status, (int) count(o, "stealer", at, Integer.MAX_VALUE),
                (int) count(o, "work_accounts", at, Integer.MAX_VALUE), (int) count(o, "personal_accounts", at, Integer.MAX_VALUE),
                count(o, "db_records", at, Long.MAX_VALUE), findings, checkedAt, sources, login, false, previous);
    }

    private static HostStatus status(String label, String at) throws Refused {
        for (HostStatus s : HostStatus.values()) {
            if (s.label().equals(label)) {
                return s;
            }
        }
        throw new Refused(at + "unknown status " + quote(label));
    }

    private static List<Finding> findings(JsonObject o, String at) throws Refused {
        if (!present(o, "findings")) {
            return List.of();
        }
        if (!(o.get("findings") instanceof JsonArray a)) {
            throw new Refused(at + "findings is not a list");
        }
        List<Finding> out = new ArrayList<>();
        for (int i = 0; i < a.size(); i++) {
            String fat = at + "finding " + (i + 1) + ": ";
            if (!(a.get(i) instanceof JsonObject f)) {
                throw new Refused(at + "finding " + (i + 1) + " is not an object");
            }
            known(f, FINDING, fat);
            out.add(new Finding(line(f, "kind", fat), line(f, "severity", fat), line(f, "confidence", fat), line(f, "name", fat),
                    null, null, null));
        }
        return out;
    }

    private static List<BreachSource> sources(JsonObject o, String at) throws Refused {
        if (!present(o, "breach_sources")) {
            return List.of();
        }
        String sat = at + "breach_sources: ";
        if (!(o.get("breach_sources") instanceof JsonArray a)) {
            throw new Refused(at + "breach_sources is not a list");
        }
        List<BreachSource> out = new ArrayList<>();
        for (JsonElement el : a) {
            if (!(el instanceof JsonObject s)) {
                throw new Refused(sat + "an entry is not an object");
            }
            known(s, SOURCE, sat);
            out.add(new BreachSource(line(s, "name", sat), text(s, "date", sat), (int) count(s, "count", sat, Integer.MAX_VALUE)));
        }
        return out;
    }

    private static LoginPage login(JsonObject o, String at) throws Refused {
        if (!present(o, "login_page")) {
            return null;
        }
        String lat = at + "login_page: ";
        if (!(o.get("login_page") instanceof JsonObject l)) {
            throw new Refused(at + "login_page is not an object");
        }
        known(l, LOGIN, lat);
        return LoginPage.exported(text(l, "type", lat), text(l, "path", lat))
                .orElseThrow(() -> new Refused(at + "login_page is not one the plugin writes"));
    }

    private static Previous previous(JsonObject o, String at, Instant now) throws Refused {
        if (!present(o, "previous")) {
            return null;
        }
        String pat = at + "previous: ";
        if (!(o.get("previous") instanceof JsonObject p)) {
            throw new Refused(at + "previous is not an object");
        }
        known(p, PREVIOUS, pat);
        return new Previous((int) count(p, "stealer", pat, Integer.MAX_VALUE), (int) count(p, "work_accounts", pat, Integer.MAX_VALUE),
                (int) count(p, "personal_accounts", pat, Integer.MAX_VALUE), count(p, "db_records", pat, Long.MAX_VALUE),
                time(p, "checked_at", pat, now));
    }

    /** Refuses the first field not in {@code allowed}. */
    private static void known(JsonObject o, Set<String> allowed, String at) throws Refused {
        for (String key : o.keySet()) {
            if (!allowed.contains(key)) {
                throw new Refused(at + "unknown field " + quote(key));
            }
        }
    }

    private static boolean present(JsonObject o, String name) {
        return o.has(name) && !o.get(name).isJsonNull();
    }

    /** A string field, or null when absent or null. */
    private static String text(JsonObject o, String name, String at) throws Refused {
        if (!present(o, name)) {
            return null;
        }
        if (!(o.get(name) instanceof JsonPrimitive p) || !p.isString()) {
            throw new Refused(at + name + " is not text");
        }
        if (p.getAsString().length() > MAX_TEXT) {
            throw new Refused(at + name + " is too long");
        }
        return p.getAsString();
    }

    /** A text shown in the tab: one plain line, as the export writes it. */
    private static String line(JsonObject o, String name, String at) throws Refused {
        return Json.oneLine(text(o, name, at));
    }

    /** A required count: plain digits only, so signs, fractions, exponents and quoted numbers are refused. */
    private static long count(JsonObject o, String name, String at, long max) throws Refused {
        if (!present(o, name)) {
            throw new Refused(at + name + " is missing");
        }
        if (o.get(name) instanceof JsonPrimitive p && p.isNumber() && p.getAsString().matches("\\d{1,19}")) {
            try {
                long v = Long.parseLong(p.getAsString());
                if (v <= max) {
                    return v;
                }
            } catch (NumberFormatException e) {
                // Past a long: refused below.
            }
        }
        throw new Refused(at + name + " is not a whole number of 0 or more");
    }

    /** An ISO time no later than a day past {@code now}, or null when absent. */
    private static Instant time(JsonObject o, String name, String at, Instant now) throws Refused {
        String s = text(o, name, at);
        if (s == null) {
            return null;
        }
        Instant t;
        try {
            t = Instant.parse(s);
        } catch (DateTimeParseException e) {
            throw new Refused(at + name + " is not a time");
        }
        if (t.isAfter(now.plus(Duration.ofDays(1)))) {
            throw new Refused(at + name + " is in the future");
        }
        return t;
    }

    /** A name from the file, quoted, on one line and cut short. */
    private static String quote(String s) {
        String line = s == null ? "" : Json.oneLine(s);
        return "\"" + (line.length() > MAX_FIELD_SHOWN ? line.substring(0, MAX_FIELD_SHOWN) + "..." : line) + "\"";
    }
}
