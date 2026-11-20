package pro.hirdman.radar.api;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/** The radar server address: scheme, host and port only. */
public record ConnectionSettings(URI server) {

    private static final Set<String> LOCAL = Set.of("localhost", "127.0.0.1", "[::1]");

    /** Parses the Server URL setting; the exception message is shown to the user. */
    public static ConnectionSettings of(@Nullable String raw) {
        String s = raw == null ? "" : raw.trim();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty()) {
            throw invalid();
        }
        URI u;
        try {
            u = new URI(s);
        } catch (URISyntaxException e) {
            throw invalid();
        }
        if (u.getScheme() == null) {
            throw httpsOnly();
        }
        String host = u.getHost();
        if (host == null || u.getRawUserInfo() != null || u.getRawQuery() != null || u.getRawFragment() != null) {
            throw invalid();
        }
        if (u.getRawPath() != null && !u.getRawPath().isEmpty()) {
            throw new IllegalArgumentException("Server URL must not contain a path");
        }
        String scheme = u.getScheme().toLowerCase(Locale.ROOT);
        host = host.toLowerCase(Locale.ROOT);
        boolean allowed = scheme.equals("https") || (scheme.equals("http") && LOCAL.contains(host));
        if (!allowed) {
            throw httpsOnly();
        }
        return new ConnectionSettings(URI.create(scheme + "://" + host + (u.getPort() == -1 ? "" : ":" + u.getPort())));
    }

    public String host() {
        return server.getHost();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Server URL is not valid");
    }

    private static IllegalArgumentException httpsOnly() {
        return new IllegalArgumentException("Server URL must start with https://");
    }
}
