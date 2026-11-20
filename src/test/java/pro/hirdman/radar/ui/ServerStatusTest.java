package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.ui.TestRadar.LIMITS;
import static pro.hirdman.radar.ui.TestRadar.META;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.config.Options;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.model.Risk;

class ServerStatusTest {

    static final String OFF_LINE = "Private project: nothing is sent to the radar server.";

    final MetaGate gate = new MetaGate();
    final TestRadar radar = new TestRadar();
    final TestLog log = new TestLog();
    final AtomicReference<Options> options = new AtomicReference<>(Options.defaults());

    ServerStatus status;

    ServerStatus status() {
        return status(Runnable::run);
    }

    final java.util.concurrent.atomic.AtomicLong now = new java.util.concurrent.atomic.AtomicLong();
    final java.util.concurrent.atomic.AtomicBoolean verifyTls = new java.util.concurrent.atomic.AtomicBoolean(true);
    final List<String> opened = new ArrayList<>();

    ServerStatus status(Executor background) {
        if (status == null) {
            status = new ServerStatus(options::get, verifyTls::get, gate, () -> radar, background, log, opened::add, now::get);
        }
        return status;
    }

    static void drainEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    static Options off() {
        Options d = Options.defaults();
        return new Options(d.serverUrl(), true, false, Risk.LOW, true, false, true, 5, false, true);
    }

    @Test
    void serverCheckShowsTheLimitsAndTheNote() throws Exception {
        assertEquals("Counts only: no accounts, passwords, raw records or dumps. Partial check, about a third of a full HIRDMAN review.",
                status().footerLabel.getText());
        status().check();
        drainEdt();
        assertEquals(LIMITS, status().label.getText());
        assertFalse(status().tryAgainButton.isVisible());
        assertEquals("Counts only, from the server. Partial check, about a third of a full HIRDMAN review.", status().footerLabel.getText());
        assertEquals(META, gate.last().orElseThrow());
    }

    @Test
    void unreachableServerOffersTryAgain() throws Exception {
        radar.answer.set(ApiException.unreachable(new IOException("refused")));
        status().check();
        drainEdt();
        assertEquals("Cannot reach scan.hirdman.pro. The plugin needs internet access, directly or through Burp's upstream proxy. Behind a proxy that re-signs HTTPS, turn off the certificate check in Settings > Extensions > Hirdman Radar.",
                status().label.getText());
        assertTrue(status().tryAgainButton.isVisible());
        assertEquals("Try again", status().tryAgainButton.getText());
        radar.answer.set(META);
        status().tryAgainButton.doClick(0);
        drainEdt();
        assertEquals(LIMITS, status().label.getText());
        assertFalse(status().tryAgainButton.isVisible());
    }

    @Test
    void unexpectedServerErrorIsLoggedAndOffersTryAgain() throws Exception {
        radar.answer.set(new IllegalStateException("boom"));
        status().check();
        drainEdt();
        assertEquals("Could not check the radar server: unexpected error. Details are in the extension's Errors tab.",
                status().label.getText());
        assertTrue(status().tryAgainButton.isVisible());
        assertEquals(List.of("Hirdman Radar: server check failed"), log.errors);
    }

    @Test
    void theReasonOfAFailedServerCheckIsLogged() throws Exception {
        radar.answer.set(ApiException.malformed("no limits in /meta", null));
        status().check();
        drainEdt();
        assertEquals("The radar server sent an unexpected answer.", status().label.getText());
        assertEquals(1, log.errors.size(), log.errors.toString());
        assertTrue(log.errors.get(0).startsWith("Hirdman Radar: server check failed: "), log.errors.get(0));
        assertTrue(log.errors.get(0).contains("no limits in /meta"), log.errors.get(0));
    }

    @Test
    void staleServerAnswerIsDropped() throws Exception {
        List<Runnable> later = new ArrayList<>();
        status(later::add);
        radar.answer.set(ApiException.unreachable(new IOException("refused")));
        status.check();
        options.set(new Options("http://bad.example", true, false, Risk.LOW, true, false, true, 5, false));
        status.check();
        later.get(0).run();
        drainEdt();
        assertEquals("Server URL must start with https://", status.label.getText());
    }

    @Test
    void aProjectTurnedOffIsShownWithoutAsking() throws Exception {
        options.set(off());
        status().check();
        drainEdt();
        assertEquals(OFF_LINE, status().label.getText());
        // Trying again would give the same line.
        assertFalse(status().tryAgainButton.isVisible());
        assertEquals(0, radar.metaCalls.get());
    }

    @Test
    void turningTheProjectOffOrOnAsksAgain() throws Exception {
        status().watch();
        drainEdt();
        options.set(new Options(Options.defaults().serverUrl(), true, true, Risk.LOW, true, false, true, 5, false, true));
        status().watch();
        drainEdt();
        assertTrue(status().label.getText().startsWith("Private project"), status().label.getText());
        options.set(Options.defaults());
        status().watch();
        drainEdt();
        assertEquals(2, radar.metaCalls.get());
    }

    @Test
    void badServerUrlIsShownWithoutAsking() throws Exception {
        options.set(new Options("http://example.com", true, false, Risk.LOW, true, false, true, 5, false));
        status().check();
        drainEdt();
        assertEquals("Server URL must start with https://", status().label.getText());
        assertEquals(0, radar.metaCalls.get());
    }

    @Test
    void serverUrlChangeAsksAgainOnceTheUrlStopsChanging() throws Exception {
        status().watch();
        drainEdt();
        assertEquals(1, radar.metaCalls.get());
        status().watch();
        assertEquals(1, radar.metaCalls.get());
        // Typing a URL changes it on every key: only the one that stays a second is asked.
        for (String url : List.of("https://o", "https://ot", "https://other.example")) {
            options.set(new Options(url, true, false, Risk.LOW, true, false, true, 5, false));
            now.addAndGet(300_000_000L);
            status().watch();
        }
        now.addAndGet(900_000_000L);
        status().watch();
        assertEquals(1, radar.metaCalls.get());
        now.addAndGet(200_000_000L);
        status().watch();
        drainEdt();
        assertEquals(2, radar.metaCalls.get());
        now.addAndGet(5_000_000_000L);
        status().watch();
        assertEquals(2, radar.metaCalls.get());
    }

    @Test
    void anAnswerForAnEarlierServerUrlLeavesTheLine() throws Exception {
        status().check();
        drainEdt();
        options.set(new Options("https://other.example", true, false, Risk.LOW, true, false, true, 5, false));
        status.label.setText("asking");
        gate.passed(java.net.URI.create("https://scan.hirdman.pro"), META);
        drainEdt();
        assertEquals("asking", status.label.getText());
        gate.passed(java.net.URI.create("https://other.example"), META);
        drainEdt();
        assertEquals("Server: other.example. " + LIMITS, status.label.getText());
    }

    @Test
    void tlsVerificationTurnedOffIsShown() throws Exception {
        status().watch();
        assertFalse(status.tlsWarning.isVisible());
        verifyTls.set(false);
        status.watch();
        assertTrue(status.tlsWarning.isVisible());
        assertEquals("TLS verification is off", status.tlsWarning.getText());
        assertTrue(status.tlsWarning.getFont().isBold());
        verifyTls.set(true);
        status.watch();
        assertFalse(status.tlsWarning.isVisible());
    }

    @Test
    void aNewerReleaseLinkOpensItsPage() throws Exception {
        radar.answer.set(new Meta(1, "0.1.0", "anonymous", META.limits(), META.notes(), "99.0.0", "https://example.org/r"));
        status().check();
        drainEdt();
        assertTrue(status.releaseLink.isVisible());
        assertEquals("Hirdman Radar 99.0.0 is available", status.releaseLink.getText());
        status.releaseLink.doClick(0);
        assertEquals(List.of("https://example.org/r"), opened);
        radar.answer.set(META);
        status.check();
        drainEdt();
        assertFalse(status.releaseLink.isVisible());
    }

    @Test
    void metaFromAJobUpdatesTheLine() throws Exception {
        status();
        gate.passed(java.net.URI.create("https://scan.hirdman.pro"), META);
        drainEdt();
        assertEquals(LIMITS, status().label.getText());
    }

    @Test
    void theServerLineKeepsItsFullTextInATip() throws Exception {
        radar.answer.set(ApiException.unreachable(new IOException("refused")));
        status().check();
        drainEdt();
        assertEquals(status().label.getText(), status().label.getToolTipText());
    }

    @Test
    void serverTextIsNeverReadAsHtml() {
        assertEquals(Boolean.TRUE, status().label.getClientProperty("html.disable"));
        assertEquals(Boolean.TRUE, status().footerLabel.getClientProperty("html.disable"));
    }

    @Test
    void limitsNowAsksAfreshAndIsNullWhenUnknown() {
        Meta.Limits fresh = new Meta.Limits(50, 1.5, 300, 120);
        radar.answer.set(new Meta(1, "0.1.0", "anonymous", fresh, META.notes()));
        assertEquals(fresh, status().limitsNow(options.get()));
        assertEquals(1, radar.metaCalls.get());
        radar.answer.set(ApiException.unreachable(new IOException("refused")));
        assertNull(status().limitsNow(options.get()));
        radar.answer.set(new IllegalStateException("boom"));
        assertNull(status().limitsNow(options.get()));
        Options bad = new Options("http://example.com", true, false, Risk.LOW, true, false, true, 5, false);
        assertNull(status().limitsNow(bad));
        assertEquals(3, radar.metaCalls.get());
        assertEquals(List.of(), log.errors);
    }
}
