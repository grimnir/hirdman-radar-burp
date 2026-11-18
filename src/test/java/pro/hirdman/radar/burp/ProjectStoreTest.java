package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.persistence.PersistedObject;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.ResultsJson;

class ProjectStoreTest {

    static final String KEY = "hirdman.radar.results";

    final Map<String, String> strings = new HashMap<>();
    final AtomicInteger writes = new AtomicInteger();
    final List<String> errors = new CopyOnWriteArrayList<>();
    RuntimeException writeFailure;

    final PersistedObject data = fake(PersistedObject.class, (m, a) -> switch (m) {
        case "getString" -> strings.get((String) a[0]);
        case "setString" -> {
            if (writeFailure != null) {
                throw writeFailure;
            }
            writes.incrementAndGet();
            strings.put((String) a[0], (String) a[1]);
            yield null;
        }
        default -> Fakes.DEFAULT;
    });
    final ProjectStore project = new ProjectStore(data, errors::add);

    @AfterEach
    void tearDown() {
        project.close();
    }

    static void check(ResultStore s, String host) {
        s.apply("example.com", new Check(false, host, 1, 2, 3, 4, 5, true, List.of()), Instant.EPOCH);
    }

    @Test
    void savedResultsThatCouldNotBeReadAreKeptBeforeTheFirstSave() {
        String newer = "{\"v\":3,\"hosts\":[]}";
        strings.put(KEY, newer);
        ResultStore s = project.load();
        assertEquals(newer, strings.get(KEY + ".unreadable"));
        assertTrue(errors.contains("Hirdman Radar: the saved results are kept unchanged in this project as " + KEY + ".unreadable"),
                errors.toString());
        check(s, "a.example.com");
        project.tick();
        assertEquals(newer, strings.get(KEY + ".unreadable"));
        assertTrue(strings.get(KEY).contains("a.example.com"));
    }

    @Test
    void skippedRowsAreKeptToo() {
        String odd = "{\"v\":1,\"hosts\":[{\"host\":\"<b>\"}]}";
        strings.put(KEY, odd);
        project.load();
        assertEquals(odd, strings.get(KEY + ".unreadable"));
    }

    @Test
    void aCleanLoadKeepsNoCopy() {
        ResultStore saved = new ResultStore();
        check(saved, "a.example.com");
        strings.put(KEY, ResultsJson.write(saved));
        project.load();
        assertFalse(strings.containsKey(KEY + ".unreadable"));
        assertEquals(List.of(), errors);
    }

    @Test
    void loadsWhatTheProjectHolds() {
        ResultStore saved = new ResultStore();
        check(saved, "a.example.com");
        strings.put(KEY, ResultsJson.write(saved));
        ResultStore s = project.load();
        assertEquals(saved.all(), s.all());
        assertEquals(0, writes.get());
    }

    @Test
    void anEmptyProjectStartsEmpty() {
        assertTrue(project.load().all().isEmpty());
        assertEquals(List.of(), errors);
    }

    @Test
    void unreadableDataIsLogged() {
        strings.put(KEY, "{broken");
        assertTrue(project.load().all().isEmpty());
        assertEquals(List.of("Hirdman Radar: saved results could not be read, starting empty",
                "Hirdman Radar: the saved results are kept unchanged in this project as " + KEY + ".unreadable"), errors);
    }

    @Test
    void changesAreSavedOnTheNextTickOnce() {
        ResultStore s = project.load();
        check(s, "a.example.com");
        check(s, "b.example.com");
        assertEquals(0, writes.get());
        project.tick();
        assertEquals(1, writes.get());
        assertEquals(ResultsJson.write(s), strings.get(KEY));
        project.tick();
        assertEquals(1, writes.get());
    }

    @Test
    void closeSavesWhatIsPendingAndStopsTheTimer() {
        ResultStore s = project.load();
        project.start();
        assertTrue(project.running());
        check(s, "a.example.com");
        project.close();
        assertFalse(project.running());
        assertEquals(1, writes.get());
        project.close();
        assertEquals(1, writes.get());
    }

    @Test
    void aFailedSaveIsLoggedAndTriedAgain() {
        ResultStore s = project.load();
        check(s, "a.example.com");
        writeFailure = new IllegalStateException("disk full");
        project.tick();
        assertEquals(List.of("Hirdman Radar: results could not be saved: java.lang.IllegalStateException: disk full"), errors);
        writeFailure = null;
        project.tick();
        assertEquals(1, writes.get());
    }

    @Test
    void periodIsThirtySeconds() {
        // Every save writes all rows into the project file; unload saves whatever is left.
        assertEquals(30, ProjectStore.EVERY.toSeconds());
    }
}
