package pro.hirdman.radar.model;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class HostResultTest {

    static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");

    static HostResult row(HostStatus status, Instant checkedAt) {
        return new HostResult("a.example.com", "example.com", status, 0, 0, 0, 0, List.of(), checkedAt);
    }

    @Test
    void onlyASuccessfulCheckOfTheLast24HoursIsFresh() {
        assertTrue(row(HostStatus.CHECKED, NOW.minus(Duration.ofHours(23))).freshAt(NOW));
        assertTrue(row(HostStatus.CLEAN, NOW.minus(Duration.ofMinutes(1))).freshAt(NOW));
        assertFalse(row(HostStatus.CLEAN, NOW.minus(Duration.ofHours(25))).freshAt(NOW));
        assertFalse(row(HostStatus.NOT_CHECKED, NOW.minus(Duration.ofMinutes(1))).freshAt(NOW));
        assertFalse(row(HostStatus.FOUND, null).freshAt(NOW));
        assertFalse(row(HostStatus.CLEAN, null).freshAt(NOW));
    }

    @Test
    void aRowKeepsAtMostTenFindings() {
        // The contract has four kinds; a server that sends thousands must not flood the issues and the project.
        List<pro.hirdman.radar.api.ServerEvent.Finding> many = java.util.stream.IntStream.range(0, 50)
                .mapToObj(i -> new pro.hirdman.radar.api.ServerEvent.Finding("stealer", "high", "firm", "F" + i, "", "", ""))
                .toList();
        HostResult r = new HostResult("a.example.com", "example.com", HostStatus.CHECKED, 0, 0, 0, 0, many, NOW);
        org.junit.jupiter.api.Assertions.assertEquals(List.of("F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9"),
                r.findings().stream().map(pro.hirdman.radar.api.ServerEvent.Finding::name).toList());
        // A project file may hold a null finding; it is dropped, not kept for the issues to trip on.
        java.util.List<pro.hirdman.radar.api.ServerEvent.Finding> withNull = new java.util.ArrayList<>(many.subList(0, 1));
        withNull.add(0, null);
        org.junit.jupiter.api.Assertions.assertEquals(many.subList(0, 1),
                new HostResult("a.example.com", "example.com", HostStatus.CHECKED, 0, 0, 0, 0, withNull, NOW).findings());
    }
}
