package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
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

    static final String TRAFFIC =
            "Check new hosts seen in traffic (in scope only, batched every 60 s, skip hosts checked in the last 24 h)";

    final Map<String, Object> values = new HashMap<>();

    Options read() {
        return RadarSettings.read(fake(SettingData.class, this::stored), off);
    }

    Object stored(String method, Object[] args) {
        return values.getOrDefault((String) args[0], switch (method) {
            case "getString" -> "";
            case "getBoolean" -> false;
            default -> 0;
        });
    }

    boolean off;

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

    @Test
    void oneSettingsPanelBecauseBurpTakesOnlyOne() {
        burpFactory = ObjectFactoryLocator.FACTORY;
        AtomicReference<SettingsPanelBuilder> builder = new AtomicReference<>();
        SettingsPanelWithData panel = fake(SettingsPanelWithData.class, this::stored);
        builder.set(fake(SettingsPanelBuilder.class, (m, a) -> m.equals("build") ? panel : builder.get()));
        ObjectFactoryLocator.FACTORY = fake(MontoyaObjectFactory.class, (m, a) -> m.equals("settingsPanel") ? builder.get()
                : fake(SettingsPanelSetting.class, Map.of()));
        List<SettingsPanel> registered = new ArrayList<>();
        MontoyaApi api = fake(MontoyaApi.class, Map.of("userInterface", fake(UserInterface.class, (m, a) -> {
            if (!m.equals("registerSettingsPanel")) {
                return Fakes.DEFAULT;
            }
            if (!registered.isEmpty()) {
                throw new IllegalStateException("Can only register a single settings panel.");
            }
            registered.add((SettingsPanel) a[0]);
            return fake(Registration.class, Map.of());
        })));
        values.put(TRAFFIC, true);
        AtomicBoolean projectOff = new AtomicBoolean();
        RadarSettings settings = new RadarSettings(api, projectOff::get);
        assertEquals(1, registered.size());
        assertSame(panel, registered.get(0));
        assertEquals(true, settings.watchTraffic());
        projectOff.set(true);
        assertEquals(false, settings.watchTraffic());
        assertEquals(true, settings.snapshot().offForProject());
    }

    static final String VERIFY_TLS = "Verify the server's TLS certificate (turn off only behind a proxy that re-signs HTTPS)";

    @Test
    void labelsAreTheSpecWording() {
        assertEquals(List.of("Server URL", VERIFY_TLS, "Create issues automatically", "Include out-of-scope hosts", "Lowest severity to report",
                "Add discovered subdomains to the site map (unrequested items)", TRAFFIC,
                "Re-check hosts that could not be checked (once, after 2 min)", "Attempts when the server is unavailable",
                "Always rescan (ignore the server's 30-minute cache)"), RadarSettings.LABELS);
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
        values.put("Attempts when the server is unavailable", 3);
        values.put("Always rescan (ignore the server's 30-minute cache)", true);
        assertEquals(new Options(" https://radar.example.com/ ", false, true, Risk.MEDIUM, false, true, false, 3, true), read());
    }

    @Test
    void oddSeverityAndAttemptsFallBack() {
        values.put("Lowest severity to report", "Critical");
        values.put("Attempts when the server is unavailable", 0);
        Options o = read();
        assertEquals(Risk.LOW, o.lowest());
        assertEquals(1, o.attempts());
        values.put("Lowest severity to report", "High");
        assertEquals(Risk.HIGH, read().lowest());
    }
}
