package pro.hirdman.radar.jobs;

import java.time.Duration;

/** Every status line of the Jobs strip. */
public final class StatusText {

    static final String SAVED_SCAN = ". Saved scan: without a key, a domain can be rescanned once an hour.";
    /** Tail of a done status for a repeat leak check of a domain. */
    public static final String REPEAT = ". Only new subdomains and failed checks were sent. Tick Rescan to scan again.";

    private StatusText() {
    }

    public static String waiting() {
        return "Waiting in plugin queue";
    }

    public static String serverQueue(int position, int etaSec) {
        return "Server queue: #" + position + ", about " + span(etaSec);
    }

    public static String finding() {
        return "Finding subdomains";
    }

    /** Time left is the unchecked hosts at the server's check rate, rounded up. */
    public static String checking(int checked, int total, double hostsPerSec) {
        String s = "Checking " + checked + " of " + total;
        if (checked >= total || hostsPerSec <= 0) {
            return s;
        }
        return s + ", about " + span((long) Math.ceil((total - checked) / hostsPerSec)) + " left";
    }

    public static String done(int hosts, int withLeaks, int failed, boolean savedScan) {
        return "Done: " + summary(hosts, withLeaks, 0, failed) + (savedScan ? SAVED_SCAN : "");
    }

    /** "120 hosts, 9 with leaks, 40 not checked yet, 3 failed"; zero parts after the leaks are left out. */
    public static String summary(long hosts, long withLeaks, long notCheckedYet, long failed) {
        return count(hosts, "host") + ", " + withLeaks + " with leaks"
                + (notCheckedYet > 0 ? ", " + notCheckedYet + " not checked yet" : "")
                + (failed > 0 ? ", " + failed + " failed" : "");
    }

    /** No answer from the server: network, proxy, or a certificate a re-signing proxy made. */
    public static String cannotReach(String host) {
        return "Cannot reach " + host + ". The plugin needs internet access, directly or through Burp's upstream proxy."
                + " Behind a proxy that re-signs HTTPS, turn off the certificate check in Settings > Extensions > Hirdman Radar.";
    }

    /** What a domain scan that hit the server's subdomain limit checked; {@code listed}: the rest are in the table. */
    public static String largePerimeter(int checked, int discovered, boolean listed) {
        return "the " + checked + " most important of " + discovered + " subdomains were checked"
                + (listed ? "; the rest are listed as Not checked yet." : ".");
    }

    /** Tail of a done status: hosts a plain check left out because they were checked in the last 24 h. */
    public static String skipped(int n) {
        if (n == 0) {
            return "";
        }
        return ". " + hosts(n) + " checked in the last 24 h " + (n == 1 ? "was" : "were") + " skipped.";
    }

    /** Status of a host check that sent nothing because every host was checked in the last 24 h. */
    public static String allFresh(int n) {
        return n == 1
                ? "Nothing sent: the host was checked in the last 24 h. Use Check again to check it anyway."
                : "Nothing sent: all " + hosts(n) + " were checked in the last 24 h. Use Check again to check them anyway.";
    }

    /** Status of a repeat leak check of a domain that found nothing to send. */
    public static String nothingNew(String domain) {
        return "Nothing new for " + domain + ": no new subdomains, all checked hosts are from the last 24 h."
                + " Tick Rescan to scan again.";
    }

    public static String doneFound(int hosts) {
        return "Done: " + hosts(hosts);
    }

    public static String retrying(String reason, Duration after, int attempt, int maxAttempts) {
        return reason + ". Retrying in " + span(after) + ", attempt " + attempt + " of " + maxAttempts + ".";
    }

    public static String rateLimited(Duration after) {
        return "Rate limited by the server. Waiting " + span(after) + ".";
    }

    public static String hourlyLimit(Duration after) {
        return "Hourly limit without a key reached. Continues in " + span(after) + ".";
    }

    public static String busy(Duration after) {
        return "Busy with other jobs from your address. Waiting " + span(after) + ".";
    }

    public static String failed(String reason) {
        return "Failed: " + reason;
    }

    public static String cancelled() {
        return "Cancelled";
    }

    static String hosts(int n) {
        return count(n, "host");
    }

    public static String count(long n, String noun) {
        return n + " " + noun + (n == 1 ? "" : "s");
    }

    private static String span(Duration d) {
        return span((long) Math.ceil(d.toMillis() / 1000.0));
    }

    /** Seconds under two minutes, whole minutes rounded up from there. */
    private static String span(long seconds) {
        return seconds < 120 ? seconds + " s" : (long) Math.ceil(seconds / 60.0) + " min";
    }
}
