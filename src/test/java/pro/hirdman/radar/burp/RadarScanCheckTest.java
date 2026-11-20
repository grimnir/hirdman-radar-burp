package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

class RadarScanCheckTest {

    final List<String> asked = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
    final HostResult row = new HostResult("vpn.example.com", "example.com", HostStatus.CHECKED, 3, 0, 0, 0, List.of(), Instant.EPOCH);
    final AuditIssue found = issue("Hirdman Radar: Host found in infostealer logs", "https://vpn.example.com/");
    RuntimeException failure;

    RadarScanCheck check() {
        return new RadarScanCheck(host -> {
            asked.add(host);
            return host.equals("vpn.example.com") ? Optional.of(row) : Optional.empty();
        }, r -> {
            if (failure != null) {
                throw failure;
            }
            return r == row ? List.of(found) : List.of();
        }, issues -> fake(AuditResult.class, Map.of("auditIssues", issues)), errors::add);
    }

    static AuditIssue issue(String name, String baseUrl) {
        return fake(AuditIssue.class, Map.of("name", name, "baseUrl", baseUrl));
    }

    static HttpRequestResponse base(String host) {
        return fake(HttpRequestResponse.class, Map.of("httpService", fake(HttpService.class, Map.of("host", host))));
    }

    @Test
    void aHostWithARowGetsItsIssuesFromMemory() {
        assertEquals(List.of(found), check().doCheck(base("vpn.example.com")).auditIssues());
        assertEquals(List.of("vpn.example.com"), asked);
    }

    @Test
    void aHostWithoutARowGetsNothing() {
        assertEquals(List.of(), check().doCheck(base("www.example.com")).auditIssues());
    }

    @Test
    void aFailureIsLoggedAndTheScanGoesOn() {
        failure = new IllegalStateException("broken");
        assertEquals(List.of(), check().doCheck(base("vpn.example.com")).auditIssues());
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).startsWith("Hirdman Radar: the scan check failed for vpn.example.com: "), errors.get(0));
    }

    @Test
    void theSameIssueOnTheSameHostIsKeptOnce() {
        RadarScanCheck c = check();
        assertEquals(ConsolidationAction.KEEP_EXISTING,
                c.consolidateIssues(found, issue("Hirdman Radar: Host found in infostealer logs", "https://vpn.example.com/")));
        assertEquals(ConsolidationAction.KEEP_BOTH,
                c.consolidateIssues(found, issue("Hirdman Radar: Host found in breached databases", "https://vpn.example.com/")));
        assertEquals(ConsolidationAction.KEEP_BOTH,
                c.consolidateIssues(found, issue("Hirdman Radar: Host found in infostealer logs", "https://mail.example.com/")));
    }

    @Test
    void theNameSaysWhoseCheckItIs() {
        assertEquals("Hirdman Radar: leaked records", check().checkName());
    }
}
