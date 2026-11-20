package pro.hirdman.radar.burp;

import static burp.api.montoya.ui.settings.SettingsPanelSetting.booleanSetting;
import static burp.api.montoya.ui.settings.SettingsPanelSetting.integerSetting;
import static burp.api.montoya.ui.settings.SettingsPanelSetting.listSetting;
import static burp.api.montoya.ui.settings.SettingsPanelSetting.stringSetting;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.settings.SettingData;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.model.Risk;

/**
 * Settings > Extensions > Hirdman Radar, kept in Burp's user settings. Burp takes one panel per extension, so the
 * per-project off switch lives in the plugin tab. Labels double as storage keys: a renamed setting starts from its
 * default.
 */
public final class RadarSettings {

    static final String SERVER_URL = "Server URL";
    static final String VERIFY_TLS = "Verify the server's TLS certificate";
    static final String AUTO_ISSUES = "Create issues automatically";
    static final String OUT_OF_SCOPE = "Include out-of-scope hosts";
    static final String LOWEST = "Lowest severity to report";
    static final String SITE_MAP = "Add discovered subdomains to the site map (unrequested items)";
    static final String TRAFFIC = "Check new in-scope hosts seen in traffic";
    static final String HIGHLIGHT = "Highlight hosts with leaks in Proxy history";
    static final String RECHECK = "Re-check hosts that could not be checked (once, after 2 min)";
    static final String ATTEMPTS = "Attempts when the server is unavailable (1 to 10)";
    static final String ALWAYS_RESCAN = "Always rescan (at most once an hour per domain)";
    static final List<String> LABELS = List.of(SERVER_URL, VERIFY_TLS, AUTO_ISSUES, OUT_OF_SCOPE, LOWEST, SITE_MAP, TRAFFIC, HIGHLIGHT, RECHECK,
            ATTEMPTS, ALWAYS_RESCAN);
    /** How Burp names a panel value in its user settings; Java keeps such keys to 80 characters. */
    static final String STORED_PREFIX = "__managedSettings__";
    private static final List<Risk> LEVELS = List.of(Risk.HIGH, Risk.MEDIUM, Risk.LOW);
    static final List<String> SEVERITIES = LEVELS.stream().map(Risk::label).toList();

    private final SettingsPanelWithData panel;
    private final BooleanSupplier offForProject;
    private final boolean issues;

    /**
     * {@code issues}: Burp has issues (not Community Edition), so the panel shows the issue settings.
     */
    public RadarSettings(MontoyaApi api, BooleanSupplier offForProject, boolean issues) {
        this.offForProject = offForProject;
        this.issues = issues;
        Options d = Options.defaults();
        List<SettingsPanelSetting> settings = new ArrayList<>(List.of(
                stringSetting(SERVER_URL, d.serverUrl()),
                booleanSetting(VERIFY_TLS, true)));
        if (issues) {
            settings.addAll(List.of(
                    booleanSetting(AUTO_ISSUES, d.autoIssues()),
                    booleanSetting(OUT_OF_SCOPE, d.includeOutOfScope()),
                    listSetting(LOWEST, SEVERITIES, d.lowest().label())));
        }
        settings.addAll(List.of(
                booleanSetting(SITE_MAP, d.addToSiteMap()),
                booleanSetting(TRAFFIC, d.watchTraffic()),
                booleanSetting(HIGHLIGHT, false),
                booleanSetting(RECHECK, d.recheckNotChecked()),
                integerSetting(ATTEMPTS, d.attempts()),
                booleanSetting(ALWAYS_RESCAN, d.alwaysRescan())));
        panel = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("Hirdman Radar")
                .withKeywords("hirdman", "radar", "leaks")
                .withSettings(settings.toArray(SettingsPanelSetting[]::new))
                .build();
        api.userInterface().registerSettingsPanel(panel);
    }

    /** Current values; cheap, so read before every job. */
    public Options snapshot() {
        return read(panel, offForProject.getAsBoolean(), issues);
    }

    /** Read on the request path (at most once a second), so only this one setting. */
    public boolean watchTraffic() {
        return watchTraffic(panel, offForProject.getAsBoolean());
    }

    /** Read on Proxy responses through a cache. Local only: the colour and note come from the table in memory. */
    public boolean highlightProxy() {
        return highlightProxy(panel);
    }

    public String serverUrl() {
        return serverUrl(panel);
    }

    /** Read on every request to the server. */
    public boolean verifyTls() {
        return verifyTls(panel);
    }

    static boolean watchTraffic(SettingData data, boolean offForProject) {
        return !offForProject && data.getBoolean(TRAFFIC);
    }

    static boolean highlightProxy(SettingData data) {
        return data.getBoolean(HIGHLIGHT);
    }

    static boolean verifyTls(SettingData data) {
        return data.getBoolean(VERIFY_TLS);
    }

    static String serverUrl(SettingData data) {
        return data.getString(SERVER_URL);
    }

    /** Without issues the panel lacks their settings: no automatic issues, the rest at their defaults. */
    static Options read(SettingData data, boolean offForProject, boolean issues) {
        Options d = Options.defaults();
        return new Options(data.getString(SERVER_URL), issues && data.getBoolean(AUTO_ISSUES),
                issues ? data.getBoolean(OUT_OF_SCOPE) : d.includeOutOfScope(), issues ? severity(data.getString(LOWEST)) : d.lowest(),
                data.getBoolean(SITE_MAP), data.getBoolean(TRAFFIC), data.getBoolean(RECHECK),
                data.getInteger(ATTEMPTS), data.getBoolean(ALWAYS_RESCAN), offForProject);
    }

    private static Risk severity(String label) {
        return LEVELS.stream().filter(r -> r.label().equals(label)).findFirst().orElse(Risk.LOW);
    }
}
