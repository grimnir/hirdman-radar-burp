package pro.hirdman.radar.burp;

import static pro.hirdman.radar.jobs.StatusText.count;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import pro.hirdman.radar.model.HostResult;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.model.Risk;

/**
 * Colours Proxy history items of hosts with High or Medium risk and notes their counts, from the table in memory only.
 * The user's own colour stays; the note is added after any notes already there.
 */
public final class ProxyHighlight implements ProxyResponseHandler {

    static final String NOTE = "Hirdman Radar: ";

    private final ResultStore store;
    private final CachedFlag enabled;
    private final Consumer<String> error;
    private final BiFunction<InterceptedResponse, Annotations, ProxyResponseReceivedAction> received;
    private final Function<InterceptedResponse, ProxyResponseToBeSentAction> toBeSent;
    private final AtomicBoolean logged = new AtomicBoolean();

    public ProxyHighlight(ResultStore store, BooleanSupplier enabled, Consumer<String> error) {
        this(store, enabled, error, ProxyResponseReceivedAction::continueWith, ProxyResponseToBeSentAction::continueWith);
    }

    /** The pass-through factories work only inside Burp, so tests hand in their own. */
    ProxyHighlight(ResultStore store, BooleanSupplier enabled, Consumer<String> error,
            BiFunction<InterceptedResponse, Annotations, ProxyResponseReceivedAction> received,
            Function<InterceptedResponse, ProxyResponseToBeSentAction> toBeSent) {
        this.store = store;
        this.enabled = new CachedFlag(enabled, Duration.ofSeconds(1));
        this.error = error;
        this.received = received;
        this.toBeSent = toBeSent;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        Annotations annotations = response.annotations();
        try {
            if (enabled.get()) {
                annotations = annotate(annotations, store.peek(response.initiatingRequest().httpService().host()));
            }
        } catch (RuntimeException e) {
            // Burp's own thread: never throw back, and log only the first failure.
            if (!logged.getAndSet(true)) {
                error.accept("Hirdman Radar: Proxy highlight skipped a response: " + e);
            }
        }
        return received.apply(response, annotations);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return toBeSent.apply(response);
    }

    private static Annotations annotate(Annotations a, Optional<HostResult> row) {
        Risk risk = row.map(HostResult::risk).orElse(Risk.NONE);
        if (risk != Risk.HIGH && risk != Risk.MEDIUM) {
            return a;
        }
        String notes = a.notes();
        if (notes != null && notes.contains(NOTE)) {
            return a;
        }
        String note = note(row.get());
        Annotations out = a.withNotes(notes == null || notes.isBlank() ? note : notes + "; " + note);
        return a.hasHighlightColor() ? out : out.withHighlightColor(risk == Risk.HIGH ? HighlightColor.RED : HighlightColor.ORANGE);
    }

    /** "Hirdman Radar: High risk, 12 infostealer records, 3 work accounts": counts that are zero are left out. */
    static String note(HostResult r) {
        List<String> parts = new ArrayList<>();
        parts.add(r.risk().label() + " risk");
        if (r.stealer() > 0) {
            parts.add(count(r.stealer(), "infostealer record"));
        }
        if (r.work() > 0) {
            parts.add(count(r.work(), "work account"));
        }
        if (r.personal() > 0) {
            parts.add(count(r.personal(), "personal account"));
        }
        return NOTE + String.join(", ", parts);
    }
}
