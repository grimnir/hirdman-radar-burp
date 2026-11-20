package pro.hirdman.radar.model;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import pro.hirdman.radar.api.Json;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;

/** Results as saved in the Burp project. A project file can come from anyone, so every row is checked on load. */
public final class ResultsJson {

    // 2: background and remediation are numbers into "texts", one copy per distinct text. 1 kept them in each finding.
    static final int VERSION = 2;
    static final String UNREADABLE = "Hirdman Radar: saved results could not be read, starting empty";
    static final String NEWER = "Hirdman Radar: saved results are from a newer plugin, starting empty";
    /** One saved block past this many characters is not parsed: a project file can come from anyone. */
    static final int MAX_CHARS = 64 * 1024 * 1024;
    /** Rows a project loads in all; far more than any scan gives. */
    static final int MAX_ROWS = 100_000;
    /** The longest string a saved row may hold; issue texts are cut well below it. */
    static final int MAX_STRING = 20_000;

    private record SavedFinding(String kind, String severity, String confidence, String name, String detail,
            JsonElement background, JsonElement remediation) {
    }

    private record SavedLogin(String kind, String label, String path) {
    }

    private record Row(String host, String domain, String status, int stealer, int work, int personal, long dbRecords,
            List<SavedFinding> findings, String checkedAt, List<BreachSource> sources, SavedLogin login) {
    }

    private record Saved(int v, List<String> texts, List<Row> hosts) {
    }

    private ResultsJson() {
    }

    public static String write(ResultStore store) {
        return write(store.all());
    }

    public static String write(Collection<HostResult> rows) {
        Map<String, Integer> texts = new LinkedHashMap<>();
        List<Row> hosts = new ArrayList<>();
        for (HostResult r : rows) {
            List<SavedFinding> findings = r.findings().stream().map(f -> new SavedFinding(f.kind(), f.severity(),
                    f.confidence(), f.name(), f.detail(), number(texts, f.background()), number(texts, f.remediation()))).toList();
            hosts.add(new Row(r.host(), r.domain(), r.status().name(), r.stealer(), r.work(), r.personal(), r.dbRecords(),
                    findings, r.checkedAt() == null ? null : r.checkedAt().toString(), r.sources(),
                    r.login() == null ? null : new SavedLogin(r.login().kind().name(), r.login().label(), r.login().path())));
        }
        return Json.GSON.toJson(new Saved(VERSION, List.copyOf(texts.keySet()), hosts));
    }

    private static JsonElement number(Map<String, Integer> texts, String text) {
        return text == null ? null : new JsonPrimitive(texts.computeIfAbsent(text, t -> texts.size()));
    }

    /** Never throws: unreadable data gives an empty store and one line in {@code errors}. */
    public static ResultStore read(String json, Consumer<String> errors) {
        ResultStore store = new ResultStore();
        readInto(store, json, errors);
        return store;
    }

    /** Adds the saved rows to {@code store}, up to {@link #MAX_ROWS} in the store. Never throws; problems go to {@code errors}. */
    public static void readInto(ResultStore store, String json, Consumer<String> errors) {
        readInto(store, json, errors, MAX_CHARS, MAX_ROWS);
    }

    static void readInto(ResultStore store, String json, Consumer<String> errors, int maxChars, int maxRows) {
        if (json == null || json.isBlank()) {
            return;
        }
        if (json.length() > maxChars) {
            errors.accept("Hirdman Radar: saved results are too large to load (" + json.length() + " characters), starting empty");
            return;
        }
        JsonObject root = object(json);
        if (root == null) {
            errors.accept(UNREADABLE);
            return;
        }
        int version = index(root.get("v"));
        if (version > VERSION) {
            errors.accept(NEWER);
            return;
        }
        if (version < 1 || !(root.get("hosts") instanceof JsonArray rows)) {
            errors.accept(UNREADABLE);
            return;
        }
        List<String> texts = root.get("texts") instanceof JsonArray a
                ? a.asList().stream().map(e -> e instanceof JsonPrimitive p && p.isString() && p.getAsString().length() <= MAX_STRING
                        ? p.getAsString() : null).toList()
                : List.of();
        int skipped = 0;
        int room = maxRows - store.size();
        boolean full = false;
        for (JsonElement el : rows) {
            Optional<HostResult> row = tooLong(el) ? Optional.empty() : row(el, texts);
            if (row.isEmpty()) {
                skipped++;
            } else if (room <= 0) {
                full = true;
                break;
            } else {
                store.put(row.get());
                room--;
            }
        }
        if (skipped > 0) {
            errors.accept("Hirdman Radar: skipped " + skipped + " saved rows that could not be read");
        }
        if (full) {
            errors.accept("Hirdman Radar: the project holds more saved rows than the plugin loads (" + maxRows
                    + "), the rest were left out");
        }
    }

    /** Whether any string in the saved row is longer than {@link #MAX_STRING}. */
    private static boolean tooLong(JsonElement el) {
        if (el instanceof JsonPrimitive p) {
            return p.isString() && p.getAsString().length() > MAX_STRING;
        }
        if (el instanceof JsonArray a) {
            return a.asList().stream().anyMatch(ResultsJson::tooLong);
        }
        return el instanceof JsonObject o && o.entrySet().stream()
                .anyMatch(e -> e.getKey().length() > MAX_STRING || tooLong(e.getValue()));
    }

    /** The top-level JSON object, or null for anything else. */
    private static JsonObject object(String json) {
        try {
            return JsonParser.parseString(json) instanceof JsonObject o ? o : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Optional<HostResult> row(JsonElement el, List<String> texts) {
        if (!el.isJsonObject()) {
            return Optional.empty();
        }
        Row r;
        try {
            r = Json.GSON.fromJson(el, Row.class);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
        Optional<String> host = HostNames.normalize(r.host());
        Optional<String> domain = HostNames.normalize(r.domain());
        Optional<HostStatus> status = status(r.status());
        if (host.isEmpty() || domain.isEmpty() || status.isEmpty() || !HostNames.within(host.get(), domain.get())) {
            return Optional.empty();
        }
        LoginPage login = r.login() == null ? null
                : LoginPage.restore(r.login().kind(), r.login().label(), r.login().path()).orElse(null);
        // Rows without a successful check carry no numbers, whatever the file says.
        if (status.get() == HostStatus.FOUND || status.get() == HostStatus.NOT_CHECKED) {
            return Optional.of(HostResult.withoutCounts(host.get(), domain.get(), status.get(), instant(r.checkedAt()))
                    .withLogin(login));
        }
        List<Finding> findings = r.findings() == null ? List.of() : r.findings().stream().filter(Objects::nonNull)
                .map(f -> new Finding(f.kind(), f.severity(), f.confidence(), f.name(), f.detail(),
                        text(f.background(), texts), text(f.remediation(), texts)))
                .toList();
        return Optional.of(new HostResult(host.get(), domain.get(), status.get(), Math.max(0, r.stealer()),
                Math.max(0, r.work()), Math.max(0, r.personal()), Math.max(0, r.dbRecords()), findings, instant(r.checkedAt()),
                r.sources(), login));
    }

    /** A version or a text number: plain digits only, so exponents, fractions and huge values give -1. */
    private static int index(JsonElement e) {
        return e instanceof JsonPrimitive p && p.isNumber() && p.getAsString().matches("\\d{1,9}")
                ? Integer.parseInt(p.getAsString()) : -1;
    }

    /** The text itself (version 1) or its number in {@code texts}; anything else is no text. */
    private static String text(JsonElement e, List<String> texts) {
        if (e instanceof JsonPrimitive p && p.isString()) {
            return p.getAsString();
        }
        int i = index(e);
        return i >= 0 && i < texts.size() ? texts.get(i) : null;
    }

    private static Optional<HostStatus> status(String name) {
        for (HostStatus s : HostStatus.values()) {
            if (s.name().equals(name)) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    private static Instant instant(String s) {
        if (s == null) {
            return null;
        }
        try {
            Instant t = Instant.parse(s);
            // A check time far in the future would keep the host from ever being checked again.
            return t.isAfter(Instant.now().plus(Duration.ofDays(1))) ? null : t;
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
