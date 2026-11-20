package pro.hirdman.radar.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Function;
import pro.hirdman.radar.model.HostResult;

/** Passive check, once per host: the host's issues come from the table in memory, never from the network. */
public final class RadarScanCheck implements PassiveScanCheck {

    static final String NAME = "Hirdman Radar: leaked records";

    private final Function<String, Optional<HostResult>> rows;
    private final Function<HostResult, List<AuditIssue>> issues;
    private final Function<List<AuditIssue>, AuditResult> result;
    private final BiConsumer<String, Throwable> error;

    /** {@code issues} is {@link BurpIssues#forScan}, which skips what Burp already has. */
    public RadarScanCheck(Function<String, Optional<HostResult>> rows, Function<HostResult, List<AuditIssue>> issues,
            BiConsumer<String, Throwable> error) {
        this(rows, issues, AuditResult::auditResult, error);
    }

    /** Burp's factories work only inside Burp, so tests pass their own. */
    RadarScanCheck(Function<String, Optional<HostResult>> rows, Function<HostResult, List<AuditIssue>> issues,
            Function<List<AuditIssue>, AuditResult> result, BiConsumer<String, Throwable> error) {
        this.rows = rows;
        this.issues = issues;
        this.result = result;
        this.error = error;
    }

    @Override
    public String checkName() {
        return NAME;
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse base) {
        String host = null;
        try {
            host = base.httpService().host();
            return result.apply(rows.apply(host).map(issues).orElse(List.of()));
        } catch (RuntimeException e) {
            error.accept("Hirdman Radar: the scan check failed for " + host, e);
            return result.apply(List.of());
        }
    }

    /** Issues of this check are one per name and host; anything else is a different issue. */
    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existing, AuditIssue added) {
        return Objects.equals(existing.name(), added.name()) && Objects.equals(existing.baseUrl(), added.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }
}
