package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.settings.SettingData;
import burp.api.montoya.ui.settings.SettingsPanel;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.model.Risk;

class RadarSettingsTest {

    static final String TRAFFIC = "Check new in-scope hosts seen in traffic";
    static final String ATTEMPTS = "Attempts when the server is unavailable (1 to 10)";
    static final String ALWAYS_RESCAN = "Always rescan (at most once an hour per domain)";

    final Map<String, Object> values = new HashMap<>();

    Options read() {
        return RadarSettings.read(fake(SettingData.class, this::stored), off, issues);
    }

    final List<String> asked = new ArrayList<>();

    Object stored(String method, Object[] args) {
        asked.add((String) args[0]);
        return values.getOrDefault((String) args[0], switch (method) {
            case "getString" -> "";
            case "getBoolean" -> false;
            default -> 0;
        });
    }

    boolean off;
    boolean issues = true;

    @Test
    void theProjectSwitchTurnsJobsAndTrafficChecksOffForThisProjectOnly() {
        values.put(TRAFFIC, true);
        SettingData user = fake(SettingData.class, (m, a) -> values.get((String) a[0]));
        assertEquals(false, read().offForProject());
        assertEquals(true, RadarSettings.watchTraffic(user, false));
        off = true;
        assertEquals(true, read().offForProject());
        assertEquals(false, RadarSettings.watchTraffic(user, true));
    }

    MontoyaObjectFactory burpFactory;

    @AfterEach
    void restoreFactory() {
        if (burpFactory != null) {
            ObjectFactoryLocator.FACTORY = burpFactory;
        }
    }

    final List<String> shown = new ArrayList<>();

    /** Burp's settings factories, faked: the panel answers from {@link #values}, {@link #shown} lists its labels. */
    SettingsPanelWithData fakeBurpFactory() {
        SettingsPanelWithData panel = fake(SettingsPanelWithData.class, this::stored);
        if (burpFactory == null) {
            burpFactory = ObjectFactoryLocator.FACTORY;
        }
        AtomicReference<SettingsPanelBuilder> builder = new AtomicReference<>();
        builder.set(fake(SettingsPanelBuilder.class, (m, a) -> m.equals("build") ? panel : builder.get()));
        ObjectFactoryLocator.FACTORY = fake(MontoyaObjectFactory.class, (m, a) -> {
            if (m.equals("settingsPanel")) {
                return builder.get();
            }
            shown.add((String) a[0]);
            return fake(SettingsPanelSetting.class, Map.of());
        });
        return panel;
    }

    static MontoyaApi api(List<SettingsPanel> registered) {
        return fake(MontoyaApi.class, Map.of("userInterface", fake(UserInterface.class, (m, a) -> {
            if (!m.equals("registerSettingsPanel")) {
                return Fakes.DEFAULT;
            }
            if (!registered.isEmpty()) {
                throw new IllegalStateException("Can only register a single settings panel.");
            }
            registered.add((SettingsPanel) a[0]);
            return fake(Registration.class, Map.of());
        })));
    }

    @Test
    void communityEditionHasNoIssueSettings() {
        fakeBurpFactory();
        values.put("Create issues automatically", true);
        RadarSettings settings = new RadarSettings(api(new ArrayList<>()), () -> false, false);
        assertEquals(RadarSettings.LABELS.stream()
                .filter(l -> !List.of("Create issues automatically", "Include out-of-scope hosts", "Lowest severity to report").contains(l))
                .toList(), shown);
        asked.clear();
        Options o = settings.snapshot();
        assertEquals(false, o.autoIssues());
        assertEquals(Options.defaults().includeOutOfScope(), o.includeOutOfScope());
        assertEquals(Options.defaults().lowest(), o.lowest());
        assertEquals(List.of(), asked.stream().filter(k -> k.contains("issues") || k.contains("severity") || k.contains("out-of-scope")).toList(),
                "settings the panel lacks are never read");
    }

    @Test
    void professionalShowsEverySetting() {
        fakeBurpFactory();
        new RadarSettings(api(new ArrayList<>()), () -> false, true);
        assertEquals(RadarSettings.LABELS, shown);
    }

    @Test
    void oneSettingsPanelBecauseBurpTakesOnlyOne() {
        SettingsPanelWithData panel = fakeBurpFactory();
        List<SettingsPanel> registered = new ArrayList<>();
        values.put(TRAFFIC, true);
        AtomicBoolean projectOff = new AtomicBoolean();
        RadarSettings settings = new RadarSettings(api(registered), projectOff::get, true);
        assertEquals(1, registered.size());
        assertSame(panel, registered.get(0));
        assertEquals(true, settings.watchTraffic());
        projectOff.set(true);
        assertEquals(false, settings.watchTraffic());
        assertEquals(true, settings.snapshot().offForProject());
    }

    static final String VERIFY_TLS = "Verify the server's TLS certificate";

    @Test
    void labelsAreTheSpecWording() {
        assertEquals(List.of("Server URL", VERIFY_TLS, "Create issues automatically", "Include out-of-scope hosts", "Lowest severity to report",
                "Add discovered subdomains to the site map (unrequested items)", TRAFFIC,
                "Highlight hosts with leaks in Proxy history", "Re-check hosts that could not be checked (once, after 2 min)", ATTEMPTS,
                ALWAYS_RESCAN), RadarSettings.LABELS);
        assertEquals(List.of("High", "Medium", "Low"), RadarSettings.SEVERITIES);
    }

    @Test
    void singleReadsForHotPaths() {
        values.put(TRAFFIC, true);
        values.put("Server URL", "https://radar.example.com");
        SettingData data = fake(SettingData.class, (m, a) -> values.get((String) a[0]));
        assertEquals(true, RadarSettings.watchTraffic(data, false));
        assertEquals("https://radar.example.com", RadarSettings.serverUrl(data));
        values.put(TRAFFIC, false);
        assertEquals(false, RadarSettings.watchTraffic(data, false));
        values.put(VERIFY_TLS, true);
        assertEquals(true, RadarSettings.verifyTls(data));
        values.put(VERIFY_TLS, false);
        assertEquals(false, RadarSettings.verifyTls(data));
        values.put("Highlight hosts with leaks in Proxy history", false);
        assertEquals(false, RadarSettings.highlightProxy(data));
        values.put("Highlight hosts with leaks in Proxy history", true);
        assertEquals(true, RadarSettings.highlightProxy(data));
    }

    @Test
    void readsEveryField() {
        values.put("Server URL", " https://radar.example.com/ ");
        values.put("Create issues automatically", false);
        values.put("Include out-of-scope hosts", true);
        values.put("Lowest severity to report", "Medium");
        values.put("Add discovered subdomains to the site map (unrequested items)", false);
        values.put(TRAFFIC, true);
        values.put("Re-check hosts that could not be checked (once, after 2 min)", false);
        values.put(ATTEMPTS, 3);
        values.put(ALWAYS_RESCAN, true);
        assertEquals(new Options(" https://radar.example.com/ ", false, true, Risk.MEDIUM, false, true, false, 3, true), read());
    }

    @Test
    void oddSeverityAndAttemptsFallBack() {
        values.put("Lowest severity to report", "Critical");
        values.put(ATTEMPTS, 0);
        Options o = read();
        assertEquals(Risk.LOW, o.lowest());
        assertEquals(1, o.attempts());
        values.put("Lowest severity to report", "High");
        assertEquals(Risk.HIGH, read().lowest());
    }

    // Burp keeps a value under "__managedSettings__" + label in Java preferences, whose keys stop at 80 characters.
    @Test
    void everyLabelFitsBurpsStorage() {
        RadarSettings.LABELS.forEach(l -> assertTrue(RadarSettings.STORED_PREFIX.length() + l.length() <= 80, l));
    }
}
