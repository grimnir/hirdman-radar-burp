package pro.hirdman.radar.burp;

import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.PayloadGenerator;
import burp.api.montoya.intruder.PayloadGeneratorProvider;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import pro.hirdman.radar.issues.IssuePlanner;
import pro.hirdman.radar.model.HostResult;

/** Intruder payloads: host names from the table in memory. Burp gives a provider no settings, so each set is its own provider. */
public final class RadarPayloads implements PayloadGeneratorProvider {

    private final String name;
    private final Supplier<List<HostResult>> rows;
    private final Predicate<HostResult> keep;
    private final Function<String, GeneratedPayload> payload;
    private final Supplier<GeneratedPayload> end;

    private RadarPayloads(String name, Supplier<List<HostResult>> rows, Predicate<HostResult> keep,
            Function<String, GeneratedPayload> payload, Supplier<GeneratedPayload> end) {
        this.name = name;
        this.rows = rows;
        this.keep = keep;
        this.payload = payload;
        this.end = end;
    }

    /** All hosts, hosts with leaks, hosts in Burp's scope. */
    public static List<RadarPayloads> all(Supplier<List<HostResult>> rows, Predicate<String> inScope) {
        return all(rows, inScope, GeneratedPayload::payload, GeneratedPayload::end);
    }

    /** Burp's factories work only inside Burp, so tests pass their own. */
    static List<RadarPayloads> all(Supplier<List<HostResult>> rows, Predicate<String> inScope,
            Function<String, GeneratedPayload> payload, Supplier<GeneratedPayload> end) {
        return List.of(
                new RadarPayloads("Hirdman Radar hosts: all", rows, r -> true, payload, end),
                new RadarPayloads("Hirdman Radar hosts: with leaks", rows, HostResult::hasLeaks, payload, end),
                new RadarPayloads("Hirdman Radar hosts: in scope", rows, r -> inScope.test(IssuePlanner.baseUrl(r.host())), payload, end));
    }

    @Override
    public String displayName() {
        return name;
    }

    /** The hosts are taken when the attack starts, so rows added later do not change it. */
    @Override
    public PayloadGenerator providePayloadGenerator(AttackConfiguration attack) {
        Iterator<String> hosts = rows.get().stream().filter(keep).map(HostResult::host).toList().iterator();
        return point -> {
            synchronized (hosts) {
                return hosts.hasNext() ? payload.apply(hosts.next()) : end.get();
            }
        };
    }
}
