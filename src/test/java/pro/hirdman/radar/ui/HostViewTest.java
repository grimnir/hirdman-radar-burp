package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.BreachSource;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;
import pro.hirdman.radar.model.LoginPage;

class HostViewTest {

    static final Instant AT = Instant.parse("2026-11-17T14:02:33Z");
    static final String NOTE = "Counts only: no accounts, passwords, raw records or dumps.";

    static Finding finding(String severity, String name) {
        return new Finding("k", severity, "tentative", name, "", "", "");
    }

    @Test
    void aHostWithLeaksShowsRiskCountsBreachAndFindings() {
        HostResult r = new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 12, 3, 40, 7,
                List.of(finding("medium", "Work accounts in leaks"), finding("high", "Host found in infostealer logs"),
                        finding("odd", "Something else")),
                AT, List.of(new BreachSource("Combo", "2024-03", 5), new BreachSource("Old", "2019", 1)));
        assertEquals(List.of("vpn.example.com: High risk.",
                "Infostealer logs: 12. Work accounts: 3. Personal accounts: 40. Database records: 7.",
                "Latest known breach: 2024-03.",
                "High: Host found in infostealer logs",
                "Medium: Work accounts in leaks",
                "Something else",
                "Checked 2026-11-17 14:02 UTC. " + NOTE), HostView.lines(r));
        assertEquals("Check again", HostView.button(r));
    }

    @Test
    void aLoginPageSeenInTrafficFollowsTheFirstLine() {
        LoginPage vpn = new LoginPage(LoginPage.Kind.KNOWN_PATH, "FortiGate SSL VPN", "/remote/login");
        String line = "Login page seen in traffic: FortiGate SSL VPN at /remote/login.";
        assertEquals(line, HostView.lines(new HostResult("a.example.com", "example.com", HostStatus.CLEAN, 0, 0, 0, 0, List.of(),
                AT).withLogin(vpn)).get(1));
        assertEquals(List.of("c.example.com was found as a subdomain of example.com and is not checked yet.", line),
                HostView.lines(new HostResult("c.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null)
                        .withLogin(vpn)));
    }

    @Test
    void otherStatesSayWhatIsKnown() {
        assertEquals(List.of("a.example.com: no leaks counted.",
                "Infostealer logs: 0. Work accounts: 0. Personal accounts: 0. Database records: 0.",
                "Checked 2026-11-17 14:02 UTC. " + NOTE),
                HostView.lines(new HostResult("a.example.com", "example.com", HostStatus.CLEAN, 0, 0, 0, 0, List.of(), AT)));
        HostResult notChecked = new HostResult("b.example.com", "example.com", HostStatus.NOT_CHECKED, 0, 0, 0, 0, List.of(), AT);
        assertEquals(List.of("b.example.com could not be checked.", "Last tried 2026-11-17 14:02 UTC."), HostView.lines(notChecked));
        assertEquals("Check again", HostView.button(notChecked));
        HostResult found = new HostResult("c.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null);
        assertEquals(List.of("c.example.com was found as a subdomain of example.com and is not checked yet."),
                HostView.lines(found));
        assertEquals("Check for leaks", HostView.button(found));
        assertEquals(List.of("d.example.com: leaks counted.",
                "Infostealer logs: 0. Work accounts: 0. Personal accounts: 1. Database records: 0.", "Odd", NOTE),
                HostView.lines(new HostResult("d.example.com", "example.com", HostStatus.CHECKED, 0, 0, 1, 0,
                        List.of(finding("odd", "Odd")), null)));
    }
}
