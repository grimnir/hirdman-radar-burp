package pro.hirdman.radar.api;

/** GET /api/v1/meta: API version, the caller's limits and the notes every finding ends with. */
public record Meta(int apiVersion, String minPluginVersion, String keyName, Limits limits, Notes notes) {

    /** {@code hostsPerHour} 0 means no hourly limit; {@code hostsLeft} is null with a key or from an older server. */
    public record Limits(int maxHosts, double hostsPerSec, int hostsPerHour, Integer hostsLeft) {

        public Limits(int maxHosts, double hostsPerSec, int hostsPerHour) {
            this(maxHosts, hostsPerSec, hostsPerHour, null);
        }
    }

    public record Notes(String database, String coverage, String countsOnly) {
    }
}
