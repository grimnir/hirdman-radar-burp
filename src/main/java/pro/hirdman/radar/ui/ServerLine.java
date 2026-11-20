package pro.hirdman.radar.ui;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import pro.hirdman.radar.Version;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.Json;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.jobs.StatusText;

/** The server line under the results table, with an optional link after it, and the footer note. */
record ServerLine(String text, boolean tryAgain, String linkText, String linkUrl) {

    static final ServerLine NONE = new ServerLine("", false);
    static final ServerLine UNEXPECTED = new ServerLine(
            "Could not check the radar server: unexpected error. Details are in the extension's Errors tab.", true);
    static final String COUNTS_ONLY = "Counts only: no accounts, passwords, raw records or dumps.";
    static final String PARTIAL = "Partial check, about a third of a full HIRDMAN review.";
    static final String RELEASES = "https://github.com/grimnir/hirdman-radar-burp/releases/latest";
    static final String DEFAULT_HOST = "scan.hirdman.pro";
    private static final int MAX_VERSION = 20;

    ServerLine(String text, boolean tryAgain) {
        this(text, tryAgain, null, null);
    }

    static ServerLine passed(Meta m, String pluginVersion) {
        return passed(m, pluginVersion, DEFAULT_HOST);
    }

    /** Names {@code host} when it is not the default server; a newer release and the server's announcement are optional. */
    static ServerLine passed(Meta m, String pluginVersion, String host) {
        String page = releasePage(m.releaseUrl());
        String need = version(m.minPluginVersion());
        if (need != null && !Version.atLeast(pluginVersion, need)) {
            return new ServerLine("This plugin is older than the server expects (" + need + "). Download the new version from "
                    + "the releases page or the BApp Store.", false, "Releases page", page);
        }
        List<String> parts = new ArrayList<>();
        if (host != null && !host.equals(DEFAULT_HOST)) {
            parts.add("Server: " + host + ".");
        }
        LimitsText.of(m.limits()).ifPresent(parts::add);
        String note = m.notes() == null ? null : Json.oneLine(m.notes().announcement());
        if (note != null && !note.isEmpty()) {
            parts.add(note);
        }
        String latest = version(m.latestPluginVersion());
        boolean newer = latest != null && !latest.isEmpty() && !Version.atLeast(pluginVersion, latest);
        return new ServerLine(String.join(" ", parts), false, newer ? "Hirdman Radar " + latest + " is available" : null,
                newer ? page : null);
    }

    static ServerLine failed(ApiException e, String host) {
        String text = switch (e.kind()) {
            case UNREACHABLE -> StatusText.cannotReach(host);
            case HTTP -> "Cannot connect to the radar server: HTTP " + e.status() + ".";
            case MALFORMED -> "The radar server sent an unexpected answer.";
        };
        return new ServerLine(text, true);
    }

    // Trying again would give the same line.
    static final ServerLine OFF_FOR_PROJECT = new ServerLine("Private project: nothing is sent to the radar server.", false);

    static ServerLine badUrl(String problem) {
        return new ServerLine(problem, false);
    }

    /** The server's counts-only note when it gave one, then the coverage line. */
    static String footer(Meta m) {
        String note = m == null || m.notes() == null ? null : Json.oneLine(m.notes().countsOnly());
        return (note == null || note.isEmpty() ? COUNTS_ONLY : note) + " " + PARTIAL;
    }

    /** A version from the server as one short line, or null. */
    private static String version(String raw) {
        String v = Json.oneLine(raw);
        return v != null && v.length() > MAX_VERSION ? v.substring(0, MAX_VERSION) : v;
    }

    /** The server's release page when it is a plain https link, otherwise the GitHub releases. */
    private static String releasePage(String raw) {
        String url = Json.oneLine(raw);
        if (url == null || !url.startsWith("https://") || url.contains(" ")) {
            return RELEASES;
        }
        try {
            return URI.create(url).getHost() == null ? RELEASES : Link.tagged(url);
        } catch (IllegalArgumentException e) {
            return RELEASES;
        }
    }
}
