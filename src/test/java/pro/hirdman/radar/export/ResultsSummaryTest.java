package pro.hirdman.radar.export;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostResult.Previous;
import pro.hirdman.radar.model.HostStatus;

class ResultsSummaryTest {

    static final Instant NOW = Instant.parse("2026-11-17T21:30:00Z");

    static Finding f(String severity) {
        return new Finding("k", severity, "tentative", "N", "", "", "");
    }

    static HostResult checked(String host, String severity, int stealer, int work, int personal, long db, String date) {
        return new HostResult(host, "example.com", HostStatus.CHECKED, stealer, work, personal, db, List.of(f(severity)), NOW,
                date == null ? List.of() : List.of(new BreachSource("S", date, 1)));
    }

    final List<HostResult> rows = List.of(
            checked("mail.example.com", "medium", 0, 0, 5, 0, null),
            new HostResult("dev.example.com", "example.com", HostStatus.CLEAN, 0, 0, 0, 0, List.of(), NOW),
            checked("vpn.example.com", "high", 12, 3, 40, 7, "2024-03"),
            new HostResult("old.example.com", "example.com", HostStatus.NOT_CHECKED, 0, 0, 0, 0, List.of(), NOW));

    @Test
    void summaryListsTheHostsWithLeaksForAReport() {
        assertEquals("""
                ## Hirdman Radar: example.com

                4 hosts, 2 with leaks, 1 failed. Hirdman Radar summary, 2026-11-17 (UTC).

                | Host | Risk | Infostealer | Work | Host logins | DB records | Latest breach |
                |---|---|---|---|---|---|---|
                | vpn.example.com | High | 12 | 3 | 40 | 7 | 2024-03 |
                | mail.example.com | Medium | 0 | 0 | 5 | 0 |  |

                Host logins are credentials for a site on the host, whoever they belong to: for a public service, its users.

                Counts only: no accounts, passwords, raw records or dumps. Partial check: about a third of a full \
                HIRDMAN review. A full review shows which accounts and devices are affected and whether the passwords still \
                work.

                Latest scan of example.com and its subdomains: https://scan.hirdman.pro/?domain=example.com
                """, ResultsSummary.markdown("example.com", rows, "https://scan.hirdman.pro", NOW));
    }

    @Test
    void withoutLeaksOrASiteTheSummaryIsShort() {
        List<HostResult> clean = List.of(new HostResult("dev.example.com", "example.com", HostStatus.CLEAN, 0, 0, 0, 0, List.of(), NOW));
        assertEquals("""
                ## Hirdman Radar: example.com

                1 host, 0 with leaks. Hirdman Radar summary, 2026-11-17 (UTC).

                No leaks were counted for the checked hosts.

                Counts only: no accounts, passwords, raw records or dumps. Partial check: about a third of a full \
                HIRDMAN review. A full review shows which accounts and devices are affected and whether the passwords still \
                work.
                """, ResultsSummary.markdown("example.com", clean, null, NOW));
    }

    @Test
    void aRecheckListsTheChangesSinceThePreviousCheck() {
        Instant before = NOW.minusSeconds(86_400);
        List<HostResult> rechecked = List.of(
                checked("vpn.example.com", "high", 15, 3, 40, 7, null).withPrevious(new Previous(3, 3, 41, 7, before)),
                checked("mail.example.com", "medium", 0, 0, 5, 0, null).withPrevious(Previous.FIRST),
                checked("same.example.com", "medium", 0, 0, 5, 0, null).withPrevious(new Previous(0, 0, 5, 0, before)),
                new HostResult("dev.example.com", "example.com", HostStatus.CLEAN, 0, 0, 0, 0, List.of(), NOW)
                        .withPrevious(Previous.FIRST));
        String md = ResultsSummary.markdown("example.com", rechecked, null, NOW);
        assertTrue(md.contains("""
                Since the previous check:

                - mail.example.com: new (first check)
                - vpn.example.com: Infostealer +12, Host logins -1

                Counts only:"""), md);
    }

    @Test
    void aRecheckWithoutChangesSaysSo() {
        List<HostResult> same = List.of(checked("vpn.example.com", "high", 3, 0, 0, 0, null)
                .withPrevious(new Previous(3, 0, 0, 0, NOW.minusSeconds(60))));
        assertTrue(ResultsSummary.markdown("example.com", same, null, NOW).contains("\n\nSince the previous check: no changes in the"
                + " counts.\n\nCounts only:"), ResultsSummary.markdown("example.com", same, null, NOW));
    }

    @Test
    void aFirstScanHasNoChangesSection() {
        List<HostResult> first = List.of(checked("vpn.example.com", "high", 3, 0, 0, 0, null).withPrevious(Previous.FIRST));
        assertFalse(ResultsSummary.markdown("example.com", first, null, NOW).contains("Since the previous check"));
    }
}
