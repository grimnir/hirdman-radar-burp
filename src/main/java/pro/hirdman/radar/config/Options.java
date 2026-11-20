package pro.hirdman.radar.config;

import java.util.Optional;
import pro.hirdman.radar.api.ConnectionSettings;
import pro.hirdman.radar.issues.IssueOptions;
import pro.hirdman.radar.model.Risk;

/** Plugin settings as one value; read before every job. {@code offForProject}: nothing goes to the server from this project. */
public record Options(String serverUrl, boolean autoIssues, boolean includeOutOfScope, Risk lowest, boolean addToSiteMap,
        boolean watchTraffic, boolean recheckNotChecked, int attempts, boolean alwaysRescan, boolean offForProject) {

    public static final String DEFAULT_SERVER = "https://scan.hirdman.pro";
    public static final int MIN_ATTEMPTS = 1;
    public static final int MAX_ATTEMPTS = 10;

    public Options {
        lowest = lowest == null ? Risk.LOW : lowest;
        attempts = Math.clamp(attempts, MIN_ATTEMPTS, MAX_ATTEMPTS);
    }

    public Options(String serverUrl, boolean autoIssues, boolean includeOutOfScope, Risk lowest, boolean addToSiteMap,
            boolean watchTraffic, boolean recheckNotChecked, int attempts, boolean alwaysRescan) {
        this(serverUrl, autoIssues, includeOutOfScope, lowest, addToSiteMap, watchTraffic, recheckNotChecked, attempts, alwaysRescan,
                false);
    }

    public static Options defaults() {
        return new Options(DEFAULT_SERVER, true, true, Risk.LOW, true, false, true, 5, false);
    }

    public IssueOptions issueOptions() {
        return new IssueOptions(autoIssues, includeOutOfScope, lowest, site());
    }

    /** The server as scheme://host[:port], or null when the Server URL cannot be used or the project is private. */
    private String site() {
        if (offForProject) {
            return null;
        }
        try {
            return ConnectionSettings.of(serverUrl).server().toString();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** The server's host name, or null when the Server URL cannot be used. */
    public String serverHost() {
        try {
            return ConnectionSettings.of(serverUrl).host();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Why the Server URL cannot be used, or empty when it can. */
    public Optional<String> serverUrlProblem() {
        try {
            ConnectionSettings.of(serverUrl);
            return Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.of(e.getMessage());
        }
    }
}
