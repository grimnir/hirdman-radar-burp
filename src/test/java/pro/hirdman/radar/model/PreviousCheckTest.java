package pro.hirdman.radar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.model.HostResult.Previous;

class PreviousCheckTest {

    static final Instant T1 = ResultStoreTest.T1;
    static final Instant T2 = ResultStoreTest.T2;
    static final Instant T3 = Instant.parse("2026-11-17T12:00:00Z");

    static Check counts(String host, int stealer, int work, int personal, long db) {
        return new Check(false, host, work, personal, db, 0, stealer, true, List.of(ResultStoreTest.finding("stealer_logs", "high")));
    }

    static Check failed(String host) {
        return new Check(false, host, 0, 0, 0, 0, 0, false, List.of());
    }

    @Test
    void aFirstCheckHasAnEmptyPreviousAndCountsAsNew() {
        ResultStore s = new ResultStore();
        HostResult r = s.apply("example.com", counts("a.example.com", 3, 0, 0, 0), T1).orElseThrow();
        assertEquals(Previous.FIRST, r.previous());
        assertTrue(r.previous().first());
        assertEquals("new", r.changeText());
        assertTrue(r.newSinceLastCheck());
        HostResult clean = s.apply("example.com", counts("b.example.com", 0, 0, 0, 0), T1).orElseThrow();
        assertEquals("", clean.changeText(), "a first check with nothing found is nothing new");
        assertFalse(clean.newSinceLastCheck());
    }

    @Test
    void aFoundHostCheckedLaterIsAFirstCheckToo() {
        ResultStore s = new ResultStore();
        s.found("example.com", List.of("a.example.com"));
        assertNull(s.host("a.example.com").orElseThrow().previous());
        assertEquals(Previous.FIRST, s.apply("example.com", counts("a.example.com", 1, 0, 0, 0), T1).orElseThrow().previous());
    }

    @Test
    void checkAgainKeepsTheCountsOneStepBack() {
        ResultStore s = new ResultStore();
        s.apply("example.com", counts("a.example.com", 3, 2, 5, 10), T1);
        HostResult r = s.apply("example.com", counts("a.example.com", 15, 2, 4, 10), T2).orElseThrow();
        assertEquals(new Previous(3, 2, 5, 10, T1), r.previous());
        assertEquals("Infostealer +12, Host logins -1", r.changeText());
        assertTrue(r.newSinceLastCheck());
        HostResult same = s.apply("example.com", counts("a.example.com", 15, 2, 4, 10), T3).orElseThrow();
        assertEquals(new Previous(15, 2, 4, 10, T2), same.previous(), "only one step back is kept");
        assertEquals("", same.changeText());
        assertFalse(same.newSinceLastCheck());
    }

    @Test
    void onlyARiseIsNew() {
        ResultStore s = new ResultStore();
        s.apply("example.com", counts("a.example.com", 3, 2, 5, 10), T1);
        HostResult down = s.apply("example.com", counts("a.example.com", 1, 2, 5, 9), T2).orElseThrow();
        assertEquals("Infostealer -2, DB records -1", down.changeText());
        assertFalse(down.newSinceLastCheck());
    }

    @Test
    void aFailedCheckKeepsTheLastCountsForTheNextOne() {
        ResultStore s = new ResultStore();
        s.apply("example.com", counts("a.example.com", 3, 0, 0, 0), T1);
        HostResult broken = s.apply("example.com", failed("a.example.com"), T2).orElseThrow();
        assertEquals(new Previous(3, 0, 0, 0, T1), broken.previous());
        assertEquals("", broken.changeText(), "a failed check has no counts to compare");
        assertFalse(broken.newSinceLastCheck());
        HostResult back = s.apply("example.com", counts("a.example.com", 5, 0, 0, 0), T3).orElseThrow();
        assertEquals(new Previous(3, 0, 0, 0, T1), back.previous());
        assertEquals("Infostealer +2", back.changeText());
    }

    @Test
    void aReplayOfTheSameCheckKeepsItsPrevious() {
        ResultStore s = new ResultStore();
        s.apply("example.com", counts("a.example.com", 3, 0, 0, 0), T1);
        s.apply("example.com", counts("a.example.com", 7, 0, 0, 0), T2);
        Check replay = new Check(false, "a.example.com", 0, 0, 0, 0, 7, true, List.of(ResultStoreTest.finding("stealer_logs", "high")),
                List.of(), T2.toString(), true);
        HostResult r = s.apply("example.com", replay, T3).orElseThrow();
        assertEquals(new Previous(3, 0, 0, 0, T1), r.previous());
        assertEquals("Infostealer +4", r.changeText());
    }

    @Test
    void theLoginPageAndThePreviousSurviveEachOther() {
        ResultStore s = new ResultStore();
        s.apply("example.com", counts("a.example.com", 3, 0, 0, 0), T1);
        s.apply("example.com", counts("a.example.com", 4, 0, 0, 0), T2);
        s.noteLogin("a.example.com", ResultStoreTest.VPN);
        HostResult r = s.host("a.example.com").orElseThrow();
        assertEquals(new Previous(3, 0, 0, 0, T1), r.previous());
        assertEquals(ResultStoreTest.VPN, r.withPrevious(null).login());
    }

    @Test
    void aFirstPreviousHasNoCounts() {
        assertEquals(Previous.FIRST, new Previous(5, 5, 5, 5, null));
        assertEquals(new Previous(0, 0, 0, 0, T1), new Previous(-1, -2, -3, -4, T1));
    }

    @Test
    void savedPreviousCountsLoadAndOldRowsLoadWithout() {
        ResultStore s = new ResultStore();
        s.apply("example.com", counts("a.example.com", 3, 0, 0, 0), T1);
        s.apply("example.com", counts("a.example.com", 4, 0, 0, 0), T2);
        s.apply("example.com", counts("b.example.com", 1, 0, 0, 0), T2);
        s.apply("example.com", failed("c.example.com"), T2);
        List<String> errors = new ArrayList<>();
        ResultStore back = ResultsJson.read(ResultsJson.write(s), errors::add);
        assertEquals(s.all(), back.all());
        assertTrue(errors.isEmpty(), errors.toString());

        String old = """
                {"v":2,"texts":[],"hosts":[{"host":"a.example.com","domain":"example.com","status":"CLEAN","stealer":0,"work":0,\
                "personal":0,"db_records":0,"findings":[],"checked_at":"2026-11-17T10:00:00Z","sources":[]}]}""";
        HostResult r = ResultsJson.read(old, errors::add).host("a.example.com").orElseThrow();
        assertNull(r.previous());
        assertEquals("", r.changeText());
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void forgedPreviousCountsAreCheckedOnLoad() {
        List<String> errors = new ArrayList<>();
        String forged = """
                {"v":2,"texts":[],"hosts":[{"host":"a.example.com","domain":"example.com","status":"CLEAN","stealer":0,"work":0,\
                "personal":0,"db_records":0,"findings":[],"checked_at":"2026-11-17T10:00:00Z","sources":[],\
                "previous":{"stealer":-4,"work":2,"personal":0,"db_records":0,"checked_at":"3026-01-01T00:00:00Z"}},\
                {"host":"b.example.com","domain":"example.com","status":"FOUND","stealer":0,"work":0,"personal":0,"db_records":0,\
                "findings":[],"sources":[],"previous":{"stealer":4,"work":0,"personal":0,"db_records":0,"checked_at":null}}]}""";
        ResultStore s = ResultsJson.read(forged, errors::add);
        assertEquals(Previous.FIRST, s.host("a.example.com").orElseThrow().previous(), "a time ahead of now is no time");
        assertNull(s.host("b.example.com").orElseThrow().previous(), "a host never checked has no previous check");
        assertTrue(errors.isEmpty(), errors.toString());
    }
}
