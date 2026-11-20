package pro.hirdman.radar.menu;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.model.HostNames;

/** What the context menu offers for the selected hosts. IPs and invalid names are dropped: the server takes names only. */
public record MenuModel(List<String> findDomains, List<String> checkHosts, @Nullable String checkLabel) {

    static final int MAX_DOMAINS = 8;

    public static MenuModel of(List<String> rawHosts) {
        List<String> hosts = rawHosts.stream().map(HostNames::normalize).flatMap(Optional::stream).distinct().toList();
        Set<String> domains = new LinkedHashSet<>();
        for (String h : hosts) {
            domains.addAll(ParentDomains.parents(h));
        }
        String label = switch (hosts.size()) {
            case 0 -> null;
            case 1 -> "Check " + hosts.get(0) + " for leaks";
            default -> "Check " + hosts.size() + " selected hosts for leaks";
        };
        return new MenuModel(domains.stream().limit(MAX_DOMAINS).toList(), hosts, label);
    }
}
