package pro.hirdman.radar.api;

/**
 * GET /api/v1/meta: API version, the caller's limits and the notes every finding ends with. {@code latestPluginVersion}
 * and {@code releaseUrl} are optional: an older server does not send them.
 */
public record Meta(int apiVersion, String minPluginVersion, String keyName, Limits limits, Notes notes,
        String latestPluginVersion, String releaseUrl) {

    public Meta(int apiVersion, String minPluginVersion, String keyName, Limits limits, Notes notes) {
        this(apiVersion, minPluginVersion, keyName, limits, notes, null, null);
    }

    /** {@code hostsPerHour} 0 means no hourly limit; {@code hostsLeft} is null with a key or from an older server. */
    public record Limits(int maxHosts, double hostsPerSec, int hostsPerHour, Integer hostsLeft) {

        public Limits(int maxHosts, double hostsPerSec, int hostsPerHour) {
            this(maxHosts, hostsPerSec, hostsPerHour, null);
        }
    }

    /** {@code announcement}: an optional one-line note from the server, such as a planned outage. */
    public record Notes(String database, String coverage, String countsOnly, String announcement) {

        public Notes(String database, String coverage, String countsOnly) {
            this(database, coverage, countsOnly, null);
        }
    }
}
