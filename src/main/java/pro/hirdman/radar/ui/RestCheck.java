package pro.hirdman.radar.ui;

import static pro.hirdman.radar.jobs.StatusText.count;

import java.util.List;
import java.util.Optional;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

/** Subdomains of a scanned domain that no check has reached yet, such as the ones a large scan leaves out. */
record RestCheck(String domain, List<String> hosts) {

    RestCheck {
        hosts = List.copyOf(hosts);
    }

    /** Present once the domain itself was checked and some of its subdomains are still only found. */
    static Optional<RestCheck> of(String domain, List<HostResult> rows) {
        if (rows.stream().noneMatch(r -> r.host().equals(domain) && r.checked())) {
            return Optional.empty();
        }
        List<String> hosts = rows.stream().filter(r -> r.status() == HostStatus.FOUND).map(HostResult::host).toList();
        return hosts.isEmpty() ? Optional.empty() : Optional.of(new RestCheck(domain, hosts));
    }

    String line() {
        return subdomains() + " " + verb() + " not checked yet.";
    }

    /** {@code limits} from a fresh /meta, or null when unknown; the hourly limit tells how long the check takes. */
    String question(Meta.Limits limits) {
        String q = "Check " + subdomains() + " that " + verb() + " not checked yet?";
        if (limits == null || limits.hostsPerHour() <= 0 || limits.hostsLeft() == null) {
            return q;
        }
        int left = limits.hostsLeft();
        q += " Your address can check " + count(left, "more host") + " this hour";
        if (hosts.size() <= left) {
            return q + ".";
        }
        int perHour = limits.hostsPerHour();
        int hours = Math.ceilDiv(hosts.size() - left, perHour);
        return q + " and " + perHour + " an hour after that, so this takes about " + hours + " h; keep Burp open.";
    }

    private String subdomains() {
        return count(hosts.size(), "subdomain") + " of " + domain;
    }

    private String verb() {
        return hosts.size() == 1 ? "is" : "are";
    }
}
