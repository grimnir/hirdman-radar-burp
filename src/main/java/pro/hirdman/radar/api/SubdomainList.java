package pro.hirdman.radar.api;

import java.util.List;

/** GET /api/v1/subdomains: discovered hosts, most important first. */
public record SubdomainList(String domain, List<Subdomain> subdomains, List<String> failedSources) {

    public SubdomainList {
        subdomains = Json.list(subdomains);
        failedSources = Json.list(failedSources);
    }

    public record Subdomain(String host, int priority) {
    }
}
