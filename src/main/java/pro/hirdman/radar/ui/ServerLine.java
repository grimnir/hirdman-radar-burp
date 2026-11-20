package pro.hirdman.radar.ui;

import pro.hirdman.radar.Version;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.Json;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.jobs.StatusText;

/** The server line under the results table, and the footer note. */
record ServerLine(String text, boolean tryAgain) {

    static final ServerLine NONE = new ServerLine("", false);
    static final ServerLine UNEXPECTED =
            new ServerLine("Server check failed: unexpected error. Details are in the extension's Errors tab.", true);
    static final String COUNTS_ONLY = "Counts only: no accounts, passwords, raw records or dumps.";
    static final String PARTIAL = "Partial check, about a third of a full HIRDMAN review.";
    private static final int MAX_VERSION = 20;

    static ServerLine passed(Meta m, String pluginVersion) {
        String need = Json.oneLine(m.minPluginVersion());
        if (need != null && !Version.atLeast(pluginVersion, need)) {
            String shown = need.length() > MAX_VERSION ? need.substring(0, MAX_VERSION) : need;
            return new ServerLine("This plugin is older than the server expects (" + shown + "). Update it from the BApp Store.",
                    false);
        }
        return new ServerLine(LimitsText.of(m.limits()).orElse(""), false);
    }

    static ServerLine failed(ApiException e, String host) {
        String text = switch (e.kind()) {
            case UNREACHABLE -> StatusText.cannotReach(host);
            case HTTP -> "Server check failed: HTTP " + e.status() + ".";
            case MALFORMED -> "Server check failed: unexpected answer.";
        };
        return new ServerLine(text, true);
    }

    static final ServerLine OFF_FOR_PROJECT = new ServerLine("Private project: nothing is sent to the radar server.", false);

    static ServerLine badUrl(String problem) {
        return new ServerLine(problem, false);
    }

    /** The server's counts-only note when it gave one, then the coverage line. */
    static String footer(Meta m) {
        String note = m == null || m.notes() == null ? null : Json.oneLine(m.notes().countsOnly());
        return (note == null || note.isEmpty() ? COUNTS_ONLY : note) + " " + PARTIAL;
    }
}
