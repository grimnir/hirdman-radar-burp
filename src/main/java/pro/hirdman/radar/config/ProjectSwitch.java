package pro.hirdman.radar.config;

import burp.api.montoya.persistence.PersistedObject;

/** The "Private project" switch, kept in the project file; read on every request, so cached. */
public final class ProjectSwitch {

    static final String KEY = "hirdman.radar.off";

    private final PersistedObject data;
    private volatile boolean off;

    public ProjectSwitch(PersistedObject data) {
        this.data = data;
        this.off = Boolean.TRUE.equals(data.getBoolean(KEY));
    }

    public boolean off() {
        return off;
    }

    public void set(boolean value) {
        off = value;
        data.setBoolean(KEY, value);
    }
}
