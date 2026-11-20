package pro.hirdman.radar.model;

import java.net.IDN;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/** Host name rules, the same as the server's: anything else never reaches the table, site map or issues. */
public final class HostNames {

    private static final Pattern SCHEME = Pattern.compile("^[a-z][a-z0-9+.-]*://", Pattern.CASE_INSENSITIVE);
    private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    /** Zones that never resolve on the internet; arpa covers home.arpa and reverse lookups. */
    private static final Set<String> INTERNAL_ZONES = Set.of("local", "localdomain", "internal", "intranet", "lan", "corp",
            "home", "arpa", "localhost", "test", "invalid", "example", "onion");

    private HostNames() {
    }

    /** The name in what was typed or pasted: a URL, user@host, host:port or *.name; empty when there is none. */
    public static Optional<String> domainInput(@Nullable String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String s = SCHEME.matcher(raw.trim()).replaceFirst("");
        if (s.startsWith("//")) {
            s = s.substring(2);
        }
        s = s.split("[/\\\\?#]", 2)[0];
        s = s.substring(s.lastIndexOf('@') + 1);
        s = s.split(":", 2)[0];
        try {
            // DNS knows national names only in their xn-- form.
            return normalize(IDN.toASCII(s.startsWith("*.") ? s.substring(2) : s));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** The domain itself or a name under it; both normalized. */
    public static boolean within(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }

    /** A valid name outside the internal zones: only such names go to the server from traffic and scope checks. */
    public static boolean isPublic(String raw) {
        return normalize(raw).filter(h -> !INTERNAL_ZONES.contains(h.substring(h.lastIndexOf('.') + 1))).isPresent();
    }

    /** Lower-cased name without the trailing dot, or empty for IPs and anything that is not a DNS name. */
    public static Optional<String> normalize(@Nullable String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String h = raw.trim().toLowerCase(Locale.ROOT);
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.isEmpty() || h.length() > 253) {
            return Optional.empty();
        }
        String[] labels = h.split("\\.", -1);
        if (labels.length < 2) {
            return Optional.empty();
        }
        for (String label : labels) {
            if (!LABEL.matcher(label).matches()) {
                return Optional.empty();
            }
        }
        // A numeric last label means an IPv4 address, not a name.
        if (labels[labels.length - 1].chars().allMatch(Character::isDigit)) {
            return Optional.empty();
        }
        return Optional.of(h);
    }
}
