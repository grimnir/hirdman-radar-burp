package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import burp.api.montoya.intruder.PayloadGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Finding;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.HostStatus;

class RadarPayloadsTest {

    static final GeneratedPayload END = fake(GeneratedPayload.class, Map.of());
    final List<HostResult> rows = new ArrayList<>(List.of(
            row("vpn.example.com", true),
            row("www.example.com", false),
            row("mail.example.com", true),
            new HostResult("new.example.com", "example.com", HostStatus.FOUND, 0, 0, 0, 0, List.of(), null)));
    final Set<String> scope = Set.of("https://vpn.example.com/", "https://www.example.com/", "https://new.example.com/");

    static HostResult row(String host, boolean leaks) {
        List<Finding> findings = leaks ? List.of(new Finding("stealer_logs", "high", "tentative", "n", "", "", "")) : List.of();
        return new HostResult(host, "example.com", leaks ? HostStatus.CHECKED : HostStatus.CLEAN, leaks ? 3 : 0, 0, 0, 0, findings,
                Instant.EPOCH);
    }

    List<RadarPayloads> providers() {
        return RadarPayloads.all(() -> List.copyOf(rows), scope::contains, Payload::new, () -> END);
    }

    record Payload(String text) implements GeneratedPayload {
        @Override
        public burp.api.montoya.core.ByteArray value() {
            throw new UnsupportedOperationException();
        }
    }

    static List<String> drain(PayloadGenerator g) {
        IntruderInsertionPoint point = fake(IntruderInsertionPoint.class, Map.of());
        List<String> out = new ArrayList<>();
        for (GeneratedPayload p = g.generatePayloadFor(point); p != END; p = g.generatePayloadFor(point)) {
            out.add(((Payload) p).text());
        }
        assertSame(END, g.generatePayloadFor(point), "the end stays the end");
        return out;
    }

    static PayloadGenerator start(RadarPayloads p) {
        return p.providePayloadGenerator(fake(AttackConfiguration.class, Map.of()));
    }

    @Test
    void threeProvidersBecauseBurpGivesOneNoSettings() {
        assertEquals(List.of("Hirdman Radar hosts: all", "Hirdman Radar hosts: with leaks", "Hirdman Radar hosts: in scope"),
                providers().stream().map(RadarPayloads::displayName).toList());
    }

    @Test
    void eachSetTakesItsHostsFromTheTable() {
        List<RadarPayloads> p = providers();
        assertEquals(List.of("vpn.example.com", "www.example.com", "mail.example.com", "new.example.com"), drain(start(p.get(0))));
        assertEquals(List.of("vpn.example.com", "mail.example.com"), drain(start(p.get(1))));
        assertEquals(List.of("vpn.example.com", "www.example.com", "new.example.com"), drain(start(p.get(2))));
    }

    @Test
    void anAttackKeepsTheHostsItStartedWith() {
        PayloadGenerator g = start(providers().get(0));
        rows.clear();
        assertEquals(4, drain(g).size());
        assertEquals(List.of(), drain(start(providers().get(0))));
    }
}
