package pro.hirdman.radar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.burp.Fakes;

/** Smoke test of initialize on a fake Burp: what gets registered in each edition, and that unload stops it all. */
class HirdmanRadarWiringTest {

    /** "Interface.method" of every call into Burp. */
    final List<String> calls = new CopyOnWriteArrayList<>();
    final List<Object[]> registrations = new CopyOnWriteArrayList<>();
    final List<String> settings = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    ExtensionUnloadingHandler unload;
    BurpSuiteEdition edition;
    MontoyaObjectFactory burpFactory = ObjectFactoryLocator.FACTORY;

    @AfterEach
    void unloadAndRestore() {
        if (unload != null) {
            unload.extensionUnloaded();
        }
        ObjectFactoryLocator.FACTORY = burpFactory;
    }

    /** A Montoya interface answering every call with an empty value or another such fake, and recording the call. */
    @SuppressWarnings("unchecked")
    <T> T burp(Class<T> type) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (p, m, args) -> {
            switch (m.getName()) {
                case "equals" -> {
                    return p == args[0];
                }
                case "hashCode" -> {
                    return System.identityHashCode(p);
                }
                case "toString" -> {
                    return type.getSimpleName();
                }
                default -> {
                }
            }
            String call = type.getSimpleName() + "." + m.getName();
            calls.add(call);
            if (m.getName().startsWith("register")) {
                registrations.add(new Object[] {call, args});
                if (args[0] instanceof ExtensionUnloadingHandler h) {
                    unload = h;
                }
            }
            if (call.equals("Logging.logToError")) {
                errors.add(String.valueOf(args[0]));
            }
            return answer(m);
        });
    }

    private Object answer(Method m) {
        Class<?> r = m.getReturnType();
        if (r == BurpSuiteEdition.class) {
            return edition;
        }
        if (r == void.class || r == String.class || r.isEnum() || r.isArray()) {
            return null;
        }
        if (r == boolean.class) {
            return false;
        }
        if (r == int.class || r == long.class || r == short.class || r == byte.class) {
            return 0;
        }
        if (r == Optional.class) {
            return Optional.empty();
        }
        if (r == List.class) {
            return List.of();
        }
        if (r == Set.class) {
            return Set.of();
        }
        if (r.isInterface() && r.getName().startsWith("burp.api.montoya")) {
            return burp(r);
        }
        return null;
    }

    /** Burp's settings factories, faked as RadarSettingsTest does; the panel answers empty values. */
    void fakeSettingsFactory() {
        SettingsPanelWithData panel = Fakes.fake(SettingsPanelWithData.class, (m, a) -> switch (m) {
            case "getString" -> "https://radar.example.com";
            case "getBoolean" -> false;
            case "getInteger" -> 3;
            default -> Fakes.DEFAULT;
        });
        AtomicReference<SettingsPanelBuilder> builder = new AtomicReference<>();
        builder.set(Fakes.fake(SettingsPanelBuilder.class, (m, a) -> m.equals("build") ? panel : builder.get()));
        ObjectFactoryLocator.FACTORY = Fakes.fake(MontoyaObjectFactory.class, (m, a) -> {
            if (m.equals("settingsPanel")) {
                return builder.get();
            }
            settings.add((String) a[0]);
            return Fakes.fake(SettingsPanelSetting.class, java.util.Map.of());
        });
    }

    void start(BurpSuiteEdition e) {
        edition = e;
        fakeSettingsFactory();
        new HirdmanRadar().initialize(burp(MontoyaApi.class));
    }

    List<String> registered() {
        return registrations.stream().map(r -> (String) r[0]).toList();
    }

    long count(String call) {
        return registered().stream().filter(call::equals).count();
    }

    static final List<String> EVERY_EDITION = List.of(
            "UserInterface.registerSuiteTab",
            "UserInterface.registerContextMenuItemsProvider",
            "UserInterface.registerHttpRequestEditorProvider",
            "UserInterface.registerSettingsPanel",
            "Http.registerHttpHandler",
            "Proxy.registerResponseHandler",
            "Extension.registerUnloadingHandler");

    @Test
    void professionalRegistersEveryPartAndThePassiveCheck() {
        start(BurpSuiteEdition.PROFESSIONAL);
        assertTrue(registered().containsAll(EVERY_EDITION), registered().toString());
        assertEquals(2, count("Scope.registerScopeChangeHandler"), "the tab's and the automatic issues'");
        assertEquals(1, count("Scanner.registerPassiveScanCheck"));
        Object[] check = registrations.stream().filter(r -> r[0].equals("Scanner.registerPassiveScanCheck")).findFirst().orElseThrow();
        assertEquals(ScanCheckType.PER_HOST, ((Object[]) check[1])[1]);
        assertEquals(3, count("Intruder.registerPayloadGeneratorProvider"));
        assertTrue(settings.contains("Create issues automatically"));
        assertEquals(List.of(), errors);
    }

    @Test
    void communityLeavesOutTheScannerAndIssues() {
        start(BurpSuiteEdition.COMMUNITY_EDITION);
        assertTrue(registered().containsAll(EVERY_EDITION), registered().toString());
        assertEquals(1, count("Scope.registerScopeChangeHandler"), "only the tab's");
        assertEquals(3, count("Intruder.registerPayloadGeneratorProvider"));
        assertFalse(calls.stream().anyMatch(c -> c.startsWith("Scanner.") || c.equals("MontoyaApi.scanner")), calls.toString());
        assertFalse(settings.contains("Create issues automatically"));
        assertEquals(List.of(), errors);
    }

    @Test
    void unloadStopsWhatInitializeStarted() {
        start(BurpSuiteEdition.PROFESSIONAL);
        unload.extensionUnloaded();
        unload = null;
        // A failing step would log "unload step failed".
        assertEquals(List.of(), errors);
    }

    @Test
    void onlyProfessionalHasTheScanner() {
        assertTrue(HirdmanRadar.hasScanner(BurpSuiteEdition.PROFESSIONAL));
        assertFalse(HirdmanRadar.hasScanner(BurpSuiteEdition.COMMUNITY_EDITION));
        assertFalse(HirdmanRadar.hasScanner(BurpSuiteEdition.ENTERPRISE_EDITION));
    }
}
