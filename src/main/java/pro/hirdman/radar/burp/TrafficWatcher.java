package pro.hirdman.radar.burp;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.traffic.NewHostBatcher;

/** Read-only look at Burp's traffic: notes in-scope hosts, never changes a request or a response. */
public final class TrafficWatcher implements HttpHandler {

    static final long PERIOD_SECONDS = 60;

    private final NewHostBatcher batcher;
    private final BooleanSupplier enabled;
    private final JobQueue queue;
    private final Consumer<String> error;
    private final AtomicBoolean loggedSkip = new AtomicBoolean();
    private final AtomicBoolean loggedResponse = new AtomicBoolean();
    private final Consumer<HttpResponseReceived> responses;
    private final Function<HttpRequestToBeSent, RequestToBeSentAction> passRequest;
    private final Function<HttpResponseReceived, ResponseReceivedAction> passResponse;
    private ScheduledExecutorService timer;
    private volatile Job last;

    /**
     * {@code enabled} is read on every request, so it must be cheap. {@code responses} gets every response except the
     * plugin's own, on Burp's threads, whatever {@code enabled} says: it only looks and sends nothing.
     */
    public TrafficWatcher(NewHostBatcher batcher, BooleanSupplier enabled, JobQueue queue, Consumer<String> error,
            Consumer<HttpResponseReceived> responses) {
        this(batcher, enabled, queue, error, responses, RequestToBeSentAction::continueWith, ResponseReceivedAction::continueWith);
    }

    /** The pass-through factories work only inside Burp, so tests hand in their own. */
    TrafficWatcher(NewHostBatcher batcher, BooleanSupplier enabled, JobQueue queue, Consumer<String> error,
            Consumer<HttpResponseReceived> responses, Function<HttpRequestToBeSent, RequestToBeSentAction> passRequest,
            Function<HttpResponseReceived, ResponseReceivedAction> passResponse) {
        this.batcher = batcher;
        this.enabled = enabled;
        this.queue = queue;
        this.error = error;
        this.responses = responses;
        this.passRequest = passRequest;
        this.passResponse = passResponse;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        // The plugin's own calls to the radar server come from EXTENSIONS and are never noted.
        try {
            if (enabled.getAsBoolean() && !request.toolSource().isFromTool(ToolType.EXTENSIONS)) {
                batcher.offer(request.httpService().host(), request.isInScope());
            }
        } catch (RuntimeException e) {
            // Burp's own thread: never throw back, and log only the first failure.
            if (!loggedSkip.getAndSet(true)) {
                error.accept("Hirdman Radar: traffic check skipped a request: " + e);
            }
        }
        return passRequest.apply(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            // Intruder, Scanner and Sequencer replay pages already seen; their volume is not worth parsing.
            if (!response.toolSource().isFromTool(ToolType.EXTENSIONS, ToolType.INTRUDER, ToolType.SCANNER, ToolType.SEQUENCER)) {
                responses.accept(response);
            }
        } catch (RuntimeException e) {
            if (!loggedResponse.getAndSet(true)) {
                error.accept("Hirdman Radar: login page check skipped a response: " + e);
            }
        }
        return passResponse.apply(response);
    }

    public synchronized void start() {
        if (timer == null) {
            timer = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "hirdman-radar-traffic");
                t.setDaemon(true);
                return t;
            });
            timer.scheduleAtFixedRate(() -> drainSafely(Instant.now()), PERIOD_SECONDS, PERIOD_SECONDS, TimeUnit.SECONDS);
        }
    }

    /** Extension unload. */
    public synchronized void close() {
        if (timer != null) {
            timer.shutdownNow();
        }
    }

    synchronized boolean running() {
        return timer != null && !timer.isShutdown();
    }

    /** One timer tick; an exception here would stop the timer for good, so it is logged instead. */
    void drainSafely(Instant now) {
        try {
            drainNow(now);
        } catch (RuntimeException e) {
            error.accept("Hirdman Radar: traffic check failed: " + e);
        }
    }

    void drainNow(Instant now) {
        if (!enabled.getAsBoolean()) {
            batcher.clear();
            return;
        }
        // While the last check waits (hourly limit, busy server), new hosts stay in the batcher instead of piling up jobs.
        Job previous = last;
        if (previous != null && !previous.state().finished()) {
            return;
        }
        List<String> hosts = batcher.drain(now);
        if (!hosts.isEmpty()) {
            last = queue.submit(JobKind.CHECK_HOSTS, null, hosts, false);
        }
    }
}
