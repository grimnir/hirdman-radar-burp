package pro.hirdman.radar;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Plugin version from the build, and version comparison for the server's min_plugin_version. */
public final class Version {

    private static final String CURRENT = load();

    private Version() {
    }

    public static String current() {
        return CURRENT;
    }

    /** True when {@code have} is the same as or newer than {@code need}; unreadable parts count as 0. */
    public static boolean atLeast(String have, String need) {
        int[] a = parse(have);
        int[] b = parse(need);
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return a[i] > b[i];
            }
        }
        return true;
    }

    private static int[] parse(String version) {
        int[] out = new int[3];
        String[] parts = version.trim().split("\\.", 3);
        for (int i = 0; i < parts.length; i++) {
            out[i] = leadingNumber(parts[i]);
        }
        return out;
    }

    private static int leadingNumber(String part) {
        int n = 0;
        for (int i = 0; i < part.length() && Character.isDigit(part.charAt(i)) && n < 100_000; i++) {
            n = n * 10 + (part.charAt(i) - '0');
        }
        return n;
    }

    private static String load() {
        Properties props = new Properties();
        try (InputStream in = Version.class.getResourceAsStream("/radar-version.properties")) {
            if (in != null) {
                props.load(in);
            }
        } catch (IOException e) {
            // The resource ships inside the jar; without it the version reads as 0.0.0.
        }
        return props.getProperty("version", "0.0.0");
    }
}
