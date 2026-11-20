package pro.hirdman.radar.jobs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.Meta;

class MetaGateTest {

    static final URI PROD = URI.create("https://scan.hirdman.pro");
    static final URI LOCAL = URI.create("http://localhost:8090");

    @Test
    void firstJobNeedsMeta() {
        MetaGate g = new MetaGate();
        assertTrue(g.needsCheck(PROD));
        assertEquals(Optional.empty(), g.last());
    }

    @Test
    void sameServerSkipsMeta() {
        MetaGate g = new MetaGate();
        g.passed(PROD, FakeRadar.META);
        assertFalse(g.needsCheck(PROD));
        assertEquals(Optional.of(FakeRadar.META), g.last());
    }

    @Test
    void changedServerNeedsMetaAgain() {
        MetaGate g = new MetaGate();
        g.passed(PROD, FakeRadar.META);
        assertTrue(g.needsCheck(LOCAL));
    }

    @Test
    void theAnswerIsGivenOnlyForItsOwnServer() {
        // A job must not take the limits of a server the user switched to meanwhile.
        MetaGate g = new MetaGate();
        g.passed(LOCAL, FakeRadar.META);
        assertEquals(Optional.empty(), g.lastFor(PROD));
        assertEquals(Optional.of(FakeRadar.META), g.lastFor(LOCAL));
    }

    @Test
    void listenersHearNewMeta() {
        MetaGate g = new MetaGate();
        AtomicInteger calls = new AtomicInteger();
        g.addListener(m -> calls.incrementAndGet());
        g.passed(PROD, new Meta(1, "0.1.0", "anonymous", new Meta.Limits(50, 1.5, 300), null));
        assertEquals(1, calls.get());
    }
}
