package pro.hirdman.radar.model;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A login page seen in Burp's traffic on a host. Labels come from a fixed list, so saved data cannot bring in its own text. */
public record LoginPage(Kind kind, String label, String path) {

    /** Weakest first: a known product path says more than an HTTP 401, which says more than a password field. */
    public enum Kind {
        PASSWORD_FORM, HTTP_AUTH, KNOWN_PATH
    }

    /** A first path segment kept as it is; anything else, encoded tokens and bidi controls included, becomes "/". */
    private static final Pattern SEGMENT = Pattern.compile("/[A-Za-z0-9._~-]{1,64}(?:/|(?=;)|\\z)");
    static final String PASSWORD_FORM = "Password form";
    /** Lower-case path prefixes of common SSO, VPN and mail sign-in pages; a prefix ending in "/" also matches without it. */
    private static final Map<String, String> PATHS = new LinkedHashMap<>();
    private static final Map<String, String> SCHEMES = Map.of("basic", "HTTP Basic sign-in", "ntlm", "NTLM sign-in",
            "negotiate", "Windows sign-in (Negotiate)", "digest", "HTTP Digest sign-in");
    private static final Set<String> LABELS = new HashSet<>();

    static {
        PATHS.put("/adfs/ls/", "AD FS sign-in");
        PATHS.put("/owa/", "Outlook on the web");
        PATHS.put("/ecp/", "Exchange admin center");
        PATHS.put("/remote/login", "FortiGate SSL VPN");
        PATHS.put("/+cscoe+/", "Cisco AnyConnect VPN");
        PATHS.put("/dana-na/", "Ivanti Connect Secure VPN");
        PATHS.put("/global-protect/", "Palo Alto GlobalProtect VPN");
        PATHS.put("/logon/logonpoint/", "Citrix Gateway");
        PATHS.put("/vpn/index.html", "Citrix Gateway");
        PATHS.put("/my.policy", "F5 BIG-IP APM");
        PATHS.put("/auth/realms/", "Keycloak sign-in");
        PATHS.put("/rdweb/", "Remote Desktop Web Access");
        PATHS.put("/wp-login.php", "WordPress login");
        PATHS.put("/cas/login", "CAS sign-in");
        LABELS.addAll(PATHS.values());
        LABELS.addAll(SCHEMES.values());
        LABELS.add(PASSWORD_FORM);
    }

    public boolean betterThan(LoginPage other) {
        return other == null || kind.compareTo(other.kind) > 0;
    }

    /**
     * The strongest sign in one response, or empty. {@code passwordField} reads the body, so it runs last and only for a
     * 200 that nothing cheaper matched. Only the start of the path is kept: deeper segments often carry reset or session
     * tokens, and the path ends up in issues and exports.
     */
    public static Optional<LoginPage> detect(String path, int status, String wwwAuthenticate, BooleanSupplier passwordField) {
        String p = path == null || path.isEmpty() ? "/" : path;
        if (status < 400 || status == 401) {
            String prefix = knownPrefix(p);
            if (prefix != null) {
                return Optional.of(new LoginPage(Kind.KNOWN_PATH, PATHS.get(prefix), prefix));
            }
        }
        if (status == 401 && wwwAuthenticate != null) {
            String label = SCHEMES.get(wwwAuthenticate.strip().split("[\\s,]", 2)[0].toLowerCase(Locale.ROOT));
            if (label != null) {
                return Optional.of(new LoginPage(Kind.HTTP_AUTH, label, firstSegment(p)));
            }
        }
        if (status == 200 && passwordField.getAsBoolean()) {
            return Optional.of(new LoginPage(Kind.PASSWORD_FORM, PASSWORD_FORM, firstSegment(p)));
        }
        return Optional.empty();
    }

    /** The listed prefix the path starts with, ignoring case, or null. */
    private static String knownPrefix(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        for (String prefix : PATHS.keySet()) {
            if (lower.startsWith(prefix) || prefix.endsWith("/") && lower.equals(prefix.substring(0, prefix.length() - 1))) {
                return prefix;
            }
        }
        return null;
    }

    /** "/admin/" for "/admin/reset/token", "/login" for "/login;jsessionid=x", "/" for anything else. */
    private static String firstSegment(String path) {
        Matcher m = SEGMENT.matcher(path);
        return m.lookingAt() ? m.group() : "/";
    }

    /** A saved login page, or empty when anything in it is not what the plugin itself writes. */
    public static Optional<LoginPage> restore(String kind, String label, String path) {
        Kind k;
        try {
            k = Kind.valueOf(kind);
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
        if (!LABELS.contains(label) || path == null) {
            return Optional.empty();
        }
        String kept = k == Kind.KNOWN_PATH ? knownPrefix(path) : firstSegment(path);
        return path.equals(kept) ? Optional.of(new LoginPage(k, label, path)) : Optional.empty();
    }
}
