package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.ResultStore;

class ProxyHighlightTest {

    /** Annotations as plain values; Burp's own work only inside Burp. */
    record Notes(String notes, HighlightColor highlightColor) {

        Annotations fake() {
            return Fakes.fake(Annotations.class, (m, a) -> switch (m) {
                case "notes" -> notes;
                case "hasNotes" -> notes != null && !notes.isEmpty();
                case "highlightColor" -> highlightColor;
                case "hasHighlightColor" -> highlightColor != null && highlightColor != HighlightColor.NONE;
                case "withNotes" -> new Notes((String) a[0], highlightColor).fake();
                case "withHighlightColor" -> new Notes(notes, (HighlightColor) a[0]).fake();
                default -> Fakes.DEFAULT;
            });
        }

        static Notes of(Annotations a) {
            return new Notes(a.notes(), a.highlightColor());
        }
    }

    final ResultStore store = new ResultStore();
    final AtomicBoolean enabled = new AtomicBoolean(true);
    final List<String> errors = new CopyOnWriteArrayList<>();

    final List<Throwable> causes = new CopyOnWriteArrayList<>();

    /** Burp's logToError(String, Throwable): the message and its cause apart. */
    void error(String message, Throwable cause) {
        errors.add(message);
        causes.add(cause);
    }
    Annotations passed;
    final ProxyResponseReceivedAction received = fake(ProxyResponseReceivedAction.class, Map.of());
    final ProxyResponseToBeSentAction toBeSent = fake(ProxyResponseToBeSentAction.class, Map.of());
    final ProxyHighlight highlight = new ProxyHighlight(store, enabled::get, this::error, (r, a) -> {
        passed = a;
        return received;
    }, r -> toBeSent);

    static Finding finding(String severity) {
        return new Finding("k", severity, "tentative", "n", "d", "b", "r");
    }

    void checked(String host, String severity, int stealer, int work, int personal) {
        store.apply("example.com", new Check(false, host, work, personal, 0, 0, stealer, true,
                severity == null ? List.of() : List.of(finding(severity))), Instant.EPOCH);
    }

    static InterceptedResponse response(String host, Notes notes) {
        HttpService service = fake(HttpService.class, Map.of("host", host));
        HttpRequest request = fake(HttpRequest.class, Map.of("httpService", service));
        return fake(InterceptedResponse.class, Map.of("initiatingRequest", request, "annotations", notes.fake()));
    }

    Notes handle(String host, Notes notes) {
        assertSame(received, highlight.handleResponseReceived(response(host, notes)));
        return Notes.of(passed);
    }

    @Test
    void highRiskHostsAreRedWithTheirCounts() {
        checked("vpn.example.com", "high", 12, 3, 0);
        assertEquals(new Notes("Hirdman Radar: High risk, 12 infostealer records, 3 work accounts", HighlightColor.RED),
                handle("VPN.example.com", new Notes("", HighlightColor.NONE)));
    }

    @Test
    void mediumRiskHostsAreOrange() {
        checked("mail.example.com", "medium", 0, 0, 1);
        assertEquals(new Notes("Hirdman Radar: Medium risk, 1 personal account", HighlightColor.ORANGE),
                handle("mail.example.com", new Notes("", HighlightColor.NONE)));
    }

    @Test
    void lowRiskCleanAndUnknownHostsAreLeftAlone() {
        checked("low.example.com", "low", 0, 0, 0);
        checked("clean.example.com", null, 0, 0, 0);
        store.found("example.com", List.of("found.example.com"));
        for (String host : List.of("low.example.com", "clean.example.com", "found.example.com", "other.example.org")) {
            assertEquals(new Notes("", HighlightColor.NONE), handle(host, new Notes("", HighlightColor.NONE)), host);
        }
    }

    @Test
    void offLeavesEverythingAlone() {
        enabled.set(false);
        checked("vpn.example.com", "high", 12, 0, 0);
        assertEquals(new Notes("", HighlightColor.NONE), handle("vpn.example.com", new Notes("", HighlightColor.NONE)));
    }

    @Test
    void theUsersColourAndNotesAreKept() {
        checked("vpn.example.com", "high", 2, 0, 0);
        assertEquals(new Notes("mine; Hirdman Radar: High risk, 2 infostealer records", HighlightColor.GREEN),
                handle("vpn.example.com", new Notes("mine", HighlightColor.GREEN)));
    }

    @Test
    void aNoteIsNotAddedTwice() {
        checked("vpn.example.com", "high", 2, 0, 0);
        Notes once = handle("vpn.example.com", new Notes(null, HighlightColor.NONE));
        assertEquals(once, handle("vpn.example.com", once));
    }

    @Test
    void aResponseThatCannotBeReadPassesAndIsLoggedOnce() {
        InterceptedResponse broken = fake(InterceptedResponse.class, (m, a) -> {
            if (m.equals("annotations")) {
                return new Notes("", HighlightColor.NONE).fake();
            }
            throw new IllegalStateException("broken " + m);
        });
        assertSame(received, highlight.handleResponseReceived(broken));
        assertSame(received, highlight.handleResponseReceived(broken));
        assertEquals(List.of("Hirdman Radar: Proxy highlight skipped a response"), errors);
        assertTrue(causes.get(0).getMessage().startsWith("broken "), causes.toString());
        assertEquals(new Notes("", HighlightColor.NONE), Notes.of(passed));
    }

    @Test
    void responsesToTheBrowserPassUnchanged() {
        assertSame(toBeSent, highlight.handleResponseToBeSent(response("a.example.com", new Notes("", HighlightColor.NONE))));
        assertNull(passed);
    }
}
