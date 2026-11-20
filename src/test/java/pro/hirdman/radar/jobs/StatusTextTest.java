package pro.hirdman.radar.jobs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class StatusTextTest {

    @Test
    void waitingAndQueue() {
        assertEquals("Waiting in plugin queue", StatusText.waiting());
        assertEquals("Server queue: #2, about 40 s", StatusText.serverQueue(2, 40));
        assertEquals("Server queue: #5, about 4 min", StatusText.serverQueue(5, 230));
        assertEquals("Finding subdomains", StatusText.finding());
    }

    @Test
    void checkingWithTimeLeft() {
        assertEquals("Checking 37 of 120, about 56 s left", StatusText.checking(37, 120, 1.5));
        assertEquals("Checking 0 of 400, about 5 min left", StatusText.checking(0, 400, 1.5));
        assertEquals("Checking 10 of 190, about 2 min left", StatusText.checking(10, 190, 1.5));
        assertEquals("Checking 120 of 120", StatusText.checking(120, 120, 1.5));
        assertEquals("Checking 3 of 9", StatusText.checking(3, 9, 0));
    }

    @Test
    void done() {
        assertEquals("Done: 120 hosts, 9 with leaks", StatusText.done(120, 9, 0, false));
        assertEquals("Done: 120 hosts, 9 with leaks, 3 failed", StatusText.done(120, 9, 3, false));
        assertEquals("120 hosts, 9 with leaks, 40 not checked yet, 3 failed", StatusText.summary(120, 9, 40, 3));
        assertEquals("1 host, 0 with leaks", StatusText.summary(1, 0, 0, 0));
        assertEquals("3 hosts, 1 with leaks, 1 failed", StatusText.summary(3, 1, 0, 1));
        assertEquals("3 hosts, 1 with leaks, 2 not checked yet", StatusText.summary(3, 1, 2, 0));
        assertEquals("Done: 1 host, 0 with leaks", StatusText.done(1, 0, 0, false));
        assertEquals("Done: 38 hosts", StatusText.doneFound(38));
        assertEquals("Done: 1 host", StatusText.doneFound(1));
        assertEquals("Done: 2 hosts, 1 with leaks. Not rescanned: the domain was scanned less than an hour ago, so that scan is shown.",
                StatusText.done(2, 1, 0, true));
    }

    @Test
    void waits() {
        assertEquals("Server unavailable (HTTP 502). Retrying in 8 s, attempt 3 of 5.",
                StatusText.retrying("Server unavailable (HTTP 502)", Duration.ofMillis(7600), 3, 5));
        assertEquals("Rate limited by the server. Waiting 60 s.", StatusText.rateLimited(Duration.ofSeconds(60)));
        assertEquals("Hourly limit reached. Continues in 40 min.", StatusText.hourlyLimit(Duration.ofSeconds(2400)));
        assertEquals("Hourly limit reached. Continues in 45 s.", StatusText.hourlyLimit(Duration.ofSeconds(45)));
        assertEquals("Hourly limit reached. Continues in 2 min.", StatusText.hourlyLimit(Duration.ofSeconds(120)));
        assertEquals("Busy with other jobs from your address. Waiting 30 s.", StatusText.busy(Duration.ofSeconds(30)));
    }

    @Test
    void endings() {
        assertEquals("Failed: The server stopped the job", StatusText.failed("The server stopped the job"));
        assertEquals("Cancelled", StatusText.cancelled());
    }

    @Test
    void skippedAndAllFreshSayWhatWasNotSent() {
        assertEquals(". 12 hosts checked in the last 24 h were skipped.", StatusText.skipped(12));
        assertEquals(". 1 host checked in the last 24 h was skipped.", StatusText.skipped(1));
        assertEquals("", StatusText.skipped(0));
        assertEquals("Nothing sent: all 12 hosts were checked in the last 24 h. Use Check again to check them anyway.",
                StatusText.allFresh(12));
        assertEquals("Nothing sent: the host was checked in the last 24 h. Use Check again to check it anyway.",
                StatusText.allFresh(1));
    }

    @Test
    void aRepeatSaysWhatItSent() {
        assertEquals("Nothing new for example.com: no new subdomains, and every host was checked in the last 24 h."
                + " Tick Rescan to scan again.", StatusText.nothingNew("example.com"));
        assertEquals(". Only new subdomains and failed checks were sent. Tick Rescan to scan again.", StatusText.REPEAT);
    }
}
