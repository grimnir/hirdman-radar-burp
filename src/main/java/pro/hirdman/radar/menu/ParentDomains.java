package pro.hirdman.radar.menu;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Domains above a host that are worth scanning, nearest first. A short zone list stands in for the public suffix list. */
public final class ParentDomains {

    private static final Set<String> TWO_LABEL_ZONES = Set.of(
            "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
            "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru", "com.ua", "org.ua", "com.tr",
            "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "com.br", "com.cn",
            "co.nz", "co.za", "co.il", "com.kz", "com.by", "co.in");

    private ParentDomains() {
    }

    /** {@code vpn.b.example.co.uk} gives {@code b.example.co.uk, example.co.uk}; an apex gives itself; a bare zone nothing. */
    public static List<String> parents(String host) {
        String[] labels = host.split("\\.");
        int n = labels.length;
        int zone = n >= 2 && TWO_LABEL_ZONES.contains(labels[n - 2] + "." + labels[n - 1]) ? 2 : 1;
        if (n <= zone) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (int i = 1; i < n - zone; i++) {
            out.add(String.join(".", List.of(labels).subList(i, n)));
        }
        return out.isEmpty() ? List.of(host) : List.copyOf(out);
    }

    /** The registrable domain of a host, or the host itself when there is none. */
    public static String base(String host) {
        List<String> p = parents(host);
        return p.isEmpty() ? host : p.get(p.size() - 1);
    }
}
