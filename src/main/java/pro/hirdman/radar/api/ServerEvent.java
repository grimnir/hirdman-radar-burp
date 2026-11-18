package pro.hirdman.radar.api;

import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Job events the plugin acts on. */
public sealed interface ServerEvent {

    /** {@code cached} is true when the server replays a saved scan instead of running one. */
    record ScanStarted(Integer hosts, boolean cached) implements ServerEvent {
    }

    record Queued(int position, int etaSec) implements ServerEvent {
    }

    record Progress(int checked, int total) implements ServerEvent {
    }

    record ErrorEvent(String message) implements ServerEvent {
        public ErrorEvent {
            message = Json.oneLine(message);
        }
    }

    record Done(int totalSubdomains, int uncheckedHosts) implements ServerEvent {
    }

    /** The scan checked only the most important subdomains. */
    record SubdomainLimit(int count, int discovered) implements ServerEvent {
    }

    /** One checked host; {@code root} marks the scanned domain itself. */
    record Check(boolean root, String domain, int hcCorpFound, int hcOriginFound, long dbEmailCount, long dbUrlCount,
            int stealerCount, Boolean hcChecked, List<Finding> findings, List<BreachSource> breachSources) implements ServerEvent {

        public Check {
            findings = Json.list(findings);
            breachSources = Json.list(breachSources);
        }

        public Check(boolean root, String domain, int hcCorpFound, int hcOriginFound, long dbEmailCount, long dbUrlCount,
                int stealerCount, Boolean hcChecked, List<Finding> findings) {
            this(root, domain, hcCorpFound, hcOriginFound, dbEmailCount, dbUrlCount, stealerCount, hcChecked, findings, List.of());
        }

        /** False when the account check did not run: the counts are unknown, not zero. */
        public boolean checked() {
            return Boolean.TRUE.equals(hcChecked);
        }

        Check withRoot(boolean isRoot) {
            return new Check(isRoot, domain, hcCorpFound, hcOriginFound, dbEmailCount, dbUrlCount, stealerCount,
                    hcChecked, findings, breachSources);
        }
    }

    record Finding(String kind, String severity, String confidence, String name, String detail, String background,
            String remediation) {

        /** Issue texts are cut to this length anyway; longer ones are cut before they are kept. */
        static final int MAX_TEXT = 10_000;
        static final int MAX_NAME = 300;

        // Every finding of a kind repeats these texts; interned, a large project holds one copy of each.
        public Finding {
            kind = shared(kind);
            severity = shared(severity);
            confidence = shared(confidence);
            name = shared(cut(name, MAX_NAME));
            detail = cut(detail, MAX_TEXT);
            background = shared(cut(background, MAX_TEXT));
            remediation = shared(cut(remediation, MAX_TEXT));
        }

        private static String shared(String s) {
            return Json.shared(s);
        }

        private static String cut(String s, int max) {
            return s != null && s.length() > max ? s.substring(0, max) : s;
        }
    }

    /**
     * One breach the host's records come from. The name is one plain line; the date is kept only as
     * YYYY, YYYY-MM or YYYY-MM-DD (the start of what the server sent), otherwise null.
     */
    record BreachSource(String name, String date, int count) {

        private static final Pattern DATE = Pattern.compile("\\d{4}(?:-(?:0[1-9]|1[0-2])(?:-(?:0[1-9]|[12]\\d|3[01]))?)?");

        public BreachSource {
            name = Json.shared(Json.oneLine(name));
            Matcher m = date == null ? null : DATE.matcher(date);
            date = m != null && m.lookingAt() ? m.group() : null;
            count = Math.max(0, count);
        }
    }

    /** Empty for events the plugin does not use; throws for a known event with unreadable data. */
    static Optional<ServerEvent> parse(JobEvent e) throws MalformedEventException {
        Class<? extends ServerEvent> type = switch (String.valueOf(e.event())) {
            case "scan_started" -> ScanStarted.class;
            case "queued" -> Queued.class;
            case "progress" -> Progress.class;
            case "error" -> ErrorEvent.class;
            case "done" -> Done.class;
            case "subdomain_limit" -> SubdomainLimit.class;
            case "domain_check", "subdomain_check" -> Check.class;
            default -> null;
        };
        if (type == null) {
            return Optional.empty();
        }
        if (e.data() == null || !e.data().isJsonObject()) {
            throw new MalformedEventException(e, "data is not an object");
        }
        ServerEvent parsed;
        try {
            parsed = Json.GSON.fromJson(e.data(), type);
        } catch (RuntimeException ex) {
            // Gson reports bad data with several unchecked types; all mean the same here.
            throw new MalformedEventException(e, ex.getMessage());
        }
        if (parsed instanceof Check c) {
            parsed = c.withRoot("domain_check".equals(e.event()));
        }
        return Optional.of(parsed);
    }
}
