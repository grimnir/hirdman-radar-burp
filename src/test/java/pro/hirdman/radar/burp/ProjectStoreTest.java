package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.persistence.PersistedObject;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.ResultsJson;

class ProjectStoreTest {

    static final String LEGACY = "hirdman.radar.results";
    static final String EXAMPLE = ProjectStore.DOMAIN_PREFIX + "example.com";
    static final String OTHER = ProjectStore.DOMAIN_PREFIX + "other.org";

    final Map<String, String> strings = new TreeMap<>();
    final List<String> written = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    RuntimeException writeFailure;

    final PersistedObject data = fake(PersistedObject.class, (m, a) -> switch (m) {
        case "getString" -> strings.get((String) a[0]);
        case "stringKeys" -> Set.copyOf(strings.keySet());
        case "setString" -> {
            if (writeFailure != null) {
                throw writeFailure;
            }
            written.add((String) a[0]);
            strings.put((String) a[0], (String) a[1]);
            yield null;
        }
        case "deleteString" -> {
            written.add("-" + a[0]);
            strings.remove((String) a[0]);
            yield null;
        }
        default -> Fakes.DEFAULT;
    });
    final ProjectStore project = new ProjectStore(data, errors::add);

    @AfterEach
    void tearDown() {
        project.close();
    }

    static void check(ResultStore s, String domain, String host) {
        s.apply(domain, new Check(false, host, 1, 2, 3, 4, 5, true, List.of()), Instant.EPOCH);
    }

    static ResultStore saved() {
        ResultStore s = new ResultStore();
        check(s, "example.com", "a.example.com");
        check(s, "other.org", "x.other.org");
        return s;
    }

    @Test
    void eachDomainIsSavedUnderItsOwnKey() {
        ResultStore s = project.load();
        check(s, "example.com", "a.example.com");
        check(s, "other.org", "x.other.org");
        project.tick();
        assertEquals(Set.of(EXAMPLE, OTHER), Set.copyOf(written));
        assertEquals(ResultsJson.write(s.domain("example.com")), strings.get(EXAMPLE));
        assertEquals(ResultsJson.write(s.domain("other.org")), strings.get(OTHER));
    }

    @Test
    void onlyChangedDomainsAreWrittenAgain() {
        ResultStore s = project.load();
        check(s, "example.com", "a.example.com");
        check(s, "other.org", "x.other.org");
        project.tick();
        written.clear();
        check(s, "example.com", "b.example.com");
        project.tick();
        assertEquals(List.of(EXAMPLE), written);
        project.tick();
        assertEquals(List.of(EXAMPLE), written);
    }

    @Test
    void aDomainWithoutRowsLosesItsKey() {
        ResultStore s = project.load();
        check(s, "example.com", "a.example.com");
        project.tick();
        s.remove(List.of("a.example.com"));
        project.tick();
        assertFalse(strings.containsKey(EXAMPLE));
    }

    @Test
    void loadsEveryDomainKey() {
        ResultStore before = saved();
        strings.put(EXAMPLE, ResultsJson.write(before.domain("example.com")));
        strings.put(OTHER, ResultsJson.write(before.domain("other.org")));
        strings.put("hirdman.radar.private", "unrelated");
        ResultStore s = project.load();
        assertEquals(Set.copyOf(before.all()), Set.copyOf(s.all()));
        assertEquals(List.of(), written);
        assertEquals(List.of(), errors);
    }

    @Test
    void theOldSingleKeyIsMovedToOneKeyPerDomain() {
        ResultStore before = saved();
        strings.put(LEGACY, ResultsJson.write(before));
        ResultStore s = project.load();
        assertEquals(before.all(), s.all());
        assertFalse(strings.containsKey(LEGACY));
        assertEquals(ResultsJson.write(before.domain("example.com")), strings.get(EXAMPLE));
        assertEquals(ResultsJson.write(before.domain("other.org")), strings.get(OTHER));
        assertEquals(List.of(), errors);
    }

    @Test
    void theOldKeyStaysWhenTheMoveFails() {
        strings.put(LEGACY, ResultsJson.write(saved()));
        writeFailure = new IllegalStateException("disk full");
        project.load();
        assertTrue(strings.containsKey(LEGACY));
        writeFailure = null;
        project.tick();
        assertFalse(strings.containsKey(LEGACY));
        assertTrue(strings.containsKey(EXAMPLE));
    }

    @Test
    void savedResultsThatCouldNotBeReadAreKeptAside() {
        String newer = "{\"v\":3,\"hosts\":[]}";
        strings.put(EXAMPLE, newer);
        ResultStore s = project.load();
        String aside = ProjectStore.UNREADABLE_PREFIX + "example.com";
        assertEquals(newer, strings.get(aside));
        assertTrue(errors.contains("Hirdman Radar: the saved results are kept unchanged in this project as " + aside),
                errors.toString());
        check(s, "example.com", "a.example.com");
        project.tick();
        assertEquals(newer, strings.get(aside));
        assertTrue(strings.get(EXAMPLE).contains("a.example.com"));
    }

    @Test
    void theOldKeyIsKeptAsideUnderItsOldName() {
        String odd = "{\"v\":1,\"hosts\":[{\"host\":\"<b>\"}]}";
        strings.put(LEGACY, odd);
        project.load();
        assertEquals(odd, strings.get(LEGACY + ".unreadable"));
        assertFalse(strings.containsKey(LEGACY));
    }

    @Test
    void bigUnreadableDataIsNotCopied() {
        String big = "{broken" + " ".repeat(ProjectStore.MAX_UNREADABLE_COPY);
        strings.put(EXAMPLE, big);
        project.load();
        assertFalse(strings.containsKey(ProjectStore.UNREADABLE_PREFIX + "example.com"));
        assertEquals(List.of("Hirdman Radar: saved results could not be read, starting empty",
                "Hirdman Radar: the unreadable saved results of example.com are too large to keep a copy, they are replaced"
                        + " on the next save of that domain"), errors);
        assertEquals(List.of(), written);
    }

    @Test
    void anUnreadableOldKeyTooBigToCopyIsLeftInPlace() {
        String big = "{broken" + " ".repeat(ProjectStore.MAX_UNREADABLE_COPY);
        strings.put(LEGACY, big);
        project.load();
        assertEquals(big, strings.get(LEGACY));
        assertFalse(strings.containsKey(LEGACY + ".unreadable"));
    }

    @Test
    void aCleanLoadKeepsNoCopy() {
        strings.put(EXAMPLE, ResultsJson.write(saved().domain("example.com")));
        project.load();
        assertEquals(List.of(EXAMPLE), List.copyOf(strings.keySet()));
        assertEquals(List.of(), errors);
    }

    @Test
    void anEmptyProjectStartsEmpty() {
        assertTrue(project.load().all().isEmpty());
        assertEquals(List.of(), errors);
    }

    @Test
    void saveNowWritesAtOnce() {
        ResultStore s = project.load();
        check(s, "example.com", "a.example.com");
        project.saveNow();
        assertEquals(List.of(EXAMPLE), written);
    }

    @Test
    void saveNowGoesThroughTheTimerWhenItRuns() throws Exception {
        ResultStore s = project.load();
        project.start();
        check(s, "example.com", "a.example.com");
        project.saveNow();
        for (int i = 0; i < 200 && written.isEmpty(); i++) {
            Thread.sleep(10);
        }
        assertEquals(List.of(EXAMPLE), written);
    }

    @Test
    void closeSavesWhatIsPendingAndStopsTheTimer() {
        ResultStore s = project.load();
        project.start();
        assertTrue(project.running());
        check(s, "example.com", "a.example.com");
        project.close();
        assertFalse(project.running());
        assertEquals(1, written.size());
        project.close();
        project.saveNow();
        assertEquals(1, written.size());
    }

    @Test
    void aFailedSaveIsLoggedAndTriedAgain() {
        ResultStore s = project.load();
        check(s, "example.com", "a.example.com");
        writeFailure = new IllegalStateException("disk full");
        project.tick();
        assertEquals(List.of("Hirdman Radar: results could not be saved: java.lang.IllegalStateException: disk full"), errors);
        writeFailure = null;
        project.tick();
        assertEquals(List.of(EXAMPLE), written);
    }

    @Test
    void periodIsThirtySeconds() {
        // A save writes only the domains that changed; finished jobs and unload save at once.
        assertEquals(30, ProjectStore.EVERY.toSeconds());
    }
}
