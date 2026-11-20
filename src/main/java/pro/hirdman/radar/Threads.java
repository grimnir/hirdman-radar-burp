package pro.hirdman.radar;

import java.util.concurrent.ThreadFactory;

/** Threads of the plugin: named daemons, so a hung one never keeps Burp from closing. */
public final class Threads {

    private Threads() {
    }

    public static ThreadFactory daemon(String name) {
        return r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        };
    }
}
