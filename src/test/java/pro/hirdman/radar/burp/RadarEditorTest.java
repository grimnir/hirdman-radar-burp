package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.awt.Component;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobState;
import pro.hirdman.radar.jobs.TestJobs;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.ui.HostView;

class RadarEditorTest {

    final ResultStore store = new ResultStore();
    final List<String> checks = new ArrayList<>();
    final List<Component> themed = new ArrayList<>();
    Job queued = waiting();
    final RadarEditor editor = new RadarEditor(store, h -> {
        checks.add(h);
        return queued;
    }, themed::add);

    static Job waiting() {
        return TestJobs.job(JobKind.CHECK_HOSTS, null, List.of("vpn.example.com"), JobState.WAITING, "Waiting");
    }

    static HttpRequestResponse rr(String host) {
        HttpService service = fake(HttpService.class, Map.of("host", host));
        HttpRequest request = fake(HttpRequest.class, Map.of("httpService", service));
        return fake(HttpRequestResponse.class, Map.of("request", request));
    }

    void check(String host, String severity) {
        List<Finding> f = severity == null ? List.of() : List.of(new Finding("k", severity, "tentative", "Leak", "", "", ""));
        store.apply("example.com", new Check(false, host, 1, 0, 0, 0, 1, true, f), Instant.EPOCH);
    }

    @Test
    void shownOnlyForHostsTheRadarKnows() {
        check("vpn.example.com", "high");
        assertTrue(editor.isEnabledFor(rr("VPN.example.com")));
        assertFalse(editor.isEnabledFor(rr("other.example.com")));
        assertFalse(editor.isEnabledFor(rr("10.0.0.1")));
        assertFalse(editor.isEnabledFor(fake(HttpRequestResponse.class, (m, a) -> null)));
        HttpRequest noService = fake(HttpRequest.class, (m, a) -> null);
        assertFalse(editor.isEnabledFor(fake(HttpRequestResponse.class, Map.of("request", noService))));
        assertFalse(editor.isEnabledFor(null));
    }

    @Test
    void readOnlyViewOfTheRow() {
        check("vpn.example.com", "high");
        HttpRequestResponse rr = rr("vpn.example.com");
        editor.setRequestResponse(rr);
        assertEquals(HostView.lines(store.host("vpn.example.com").orElseThrow()), editor.lineTexts());
        assertEquals("Hirdman Radar", editor.caption());
        assertSame(rr.request(), editor.getRequest());
        assertFalse(editor.isModified());
        assertNull(editor.selectedData());
        assertEquals(List.of(editor.uiComponent()), themed);
    }

    @Test
    void serverOrProjectTextIsNeverReadAsHtml() {
        Finding odd = new Finding("k", "info", "tentative", "<html><img src='http://127.0.0.1:9/x'>", "", "", "");
        store.apply("example.com", new Check(false, "vpn.example.com", 1, 0, 0, 0, 1, true, List.of(odd)), Instant.EPOCH);
        editor.setRequestResponse(rr("vpn.example.com"));
        javax.swing.JPanel lines = (javax.swing.JPanel) ((javax.swing.JPanel) editor.uiComponent()).getComponent(0);
        for (Component c : lines.getComponents()) {
            assertNull(((javax.swing.JLabel) c).getClientProperty("html"), ((javax.swing.JLabel) c).getText());
        }
        assertTrue(editor.lineTexts().contains("<html><img src='http://127.0.0.1:9/x'>"), editor.lineTexts().toString());
    }

    @Test
    void checkAgainQueuesTheHostAndTheViewCatchesUp() {
        check("vpn.example.com", null);
        editor.setRequestResponse(rr("vpn.example.com"));
        assertEquals("Check again", editor.button.getText());
        editor.button.doClick(0);
        assertEquals(List.of("vpn.example.com"), checks);
        assertFalse(editor.button.isEnabled());
        assertEquals("Queued. The result shows here and in the Hirdman Radar tab.", editor.queuedLabel.getText());
        check("vpn.example.com", "high");
        editor.refresh();
        assertEquals("vpn.example.com: High risk.", editor.lineTexts().get(0));
        assertTrue(editor.button.isEnabled());
        assertEquals("", editor.queuedLabel.getText());
    }

    @Test
    void aFailedOrCancelledCheckSaysWhyAndCanBeClickedAgain() {
        check("vpn.example.com", null);
        editor.setRequestResponse(rr("vpn.example.com"));
        editor.button.doClick(0);
        TestJobs.update(queued, JobState.FAILED, "Failed: Server unavailable (HTTP 502).");
        editor.refresh();
        assertEquals("Failed: Server unavailable (HTTP 502).", editor.queuedLabel.getText());
        assertTrue(editor.button.isEnabled());
        queued = waiting();
        editor.button.doClick(0);
        assertEquals(RadarEditor.QUEUED, editor.queuedLabel.getText());
        assertFalse(editor.button.isEnabled());
        TestJobs.update(queued, JobState.CANCELLED, "Cancelled");
        editor.refresh();
        assertEquals("Cancelled", editor.queuedLabel.getText());
        assertTrue(editor.button.isEnabled());
        assertEquals(List.of("vpn.example.com", "vpn.example.com"), checks);
    }

    @Test
    void aCheckThatEndsWithoutChangingTheRowFreesTheButton() {
        check("vpn.example.com", null);
        editor.setRequestResponse(rr("vpn.example.com"));
        editor.button.doClick(0);
        TestJobs.update(queued, JobState.DONE, "Done: 1 host, 0 with leaks");
        editor.refresh();
        assertEquals("", editor.queuedLabel.getText());
        assertTrue(editor.button.isEnabled());
    }

    @Test
    void aCheckWaitingForTheLimitSaysSoAndTheWholeTextIsInTheTip() {
        check("vpn.example.com", null);
        editor.setRequestResponse(rr("vpn.example.com"));
        editor.button.doClick(0);
        TestJobs.update(queued, JobState.RETRYING, "Hourly limit reached. Continues in 40 min.");
        editor.refresh();
        assertEquals("Hourly limit reached. Continues in 40 min.", editor.queuedLabel.getText());
        assertEquals(editor.queuedLabel.getText(), editor.queuedLabel.getToolTipText());
        assertFalse(editor.button.isEnabled());
        TestJobs.update(queued, JobState.FAILED, "<html>Failed: x");
        editor.refresh();
        assertEquals(" <html>Failed: x", editor.queuedLabel.getToolTipText());
    }
}
