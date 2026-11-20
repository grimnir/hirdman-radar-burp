package pro.hirdman.radar.jobs;

import java.time.Duration;
import java.util.function.DoubleSupplier;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.api.ApiException;

/** What to do after a failed call: wait and try again, or give up with a reason for the user. */
public final class RetryPolicy {

    public enum Wait { BACKOFF, RATE_LIMIT, HOURLY_LIMIT, BUSY }

    public sealed interface Decision permits Retry, Fail {
    }

    /** {@code countsAsAttempt} is false for rate limits: waiting for them does not use up attempts. */
    public record Retry(Duration after, boolean countsAsAttempt, Wait kind, String reason) implements Decision {
    }

    public record Fail(@Nullable String reason) implements Decision {
    }

    static final Duration MAX_BACKOFF_RETRY_AFTER = Duration.ofMinutes(2);
    static final Duration RATE_LIMIT_BUDGET = Duration.ofMinutes(70);
    /** The server cancels a job nobody polls for 60 s, so a poll never waits longer than this. */
    static final Duration MAX_POLL_WAIT = Duration.ofSeconds(45);
    /** Tries of a poll whose answer could not be read; polling again with the same cursor loses nothing. */
    static final int MALFORMED_POLL_ATTEMPTS = 3;
    static final String MALFORMED = "Unexpected answer from the server";

    private static final int[] BACKOFF_SECONDS = {2, 4, 8, 16, 30};

    private RetryPolicy() {
    }

    /**
     * {@code attemptsUsed} counts the failed tries before this one; the try that just failed is number
     * {@code attemptsUsed + 1}, and {@code maxAttempts} tries are made at most. {@code poll}: the call reads a live
     * server job, so its waits are capped and an unreadable answer is tried again.
     */
    public static Decision decide(ApiException e, int attemptsUsed, int maxAttempts, Duration waitedOn429,
            String serverHost, DoubleSupplier random, boolean poll) {
        if (e.blocked()) {
            return new Fail(e.getMessage());
        }
        if (e.kind() == ApiException.Kind.MALFORMED) {
            return poll
                    ? backoff(e, attemptsUsed, Math.min(maxAttempts, MALFORMED_POLL_ATTEMPTS), random, MALFORMED, MALFORMED, poll)
                    : new Fail(MALFORMED);
        }
        if (e.kind() == ApiException.Kind.UNREACHABLE) {
            return backoff(e, attemptsUsed, maxAttempts, random, "Server unreachable",
                    StatusText.cannotReach(serverHost), poll);
        }
        int status = e.status();
        if (status == 429) {
            return rateLimit(e, waitedOn429, poll);
        }
        if (status == 401) {
            return new Fail(StatusText.notTakingChecks());
        }
        if (status == 500 || status == 502 || status == 503 || status == 504 || (status >= 520 && status <= 524)) {
            String reason = "Server unavailable (HTTP " + status + ")";
            return backoff(e, attemptsUsed, maxAttempts, random, reason, reason, poll);
        }
        return new Fail(e.serverMessage() != null && !e.serverMessage().isEmpty() ? e.serverMessage() : "HTTP " + status);
    }

    private static Decision backoff(ApiException e, int attemptsUsed, int maxAttempts, DoubleSupplier random,
            String reason, String finalReason, boolean poll) {
        if (attemptsUsed + 1 >= maxAttempts) {
            return new Fail(finalReason);
        }
        Duration after = e.retryAfter()
                .map(d -> d.compareTo(MAX_BACKOFF_RETRY_AFTER) > 0 ? MAX_BACKOFF_RETRY_AFTER : atLeastASecond(d))
                .orElseGet(() -> {
                    int base = BACKOFF_SECONDS[Math.min(Math.max(attemptsUsed, 0), BACKOFF_SECONDS.length - 1)];
                    return Duration.ofMillis(Math.round(base * 1000 * (0.8 + 0.4 * random.getAsDouble())));
                });
        return new Retry(capped(after, poll), true, Wait.BACKOFF, reason);
    }

    private static Duration capped(Duration after, boolean poll) {
        return poll && after.compareTo(MAX_POLL_WAIT) > 0 ? MAX_POLL_WAIT : after;
    }

    private static Decision rateLimit(ApiException e, Duration waitedOn429, boolean poll) {
        String msg = e.serverMessage() == null ? "" : e.serverMessage();
        Wait kind;
        String reason;
        Duration fallback;
        if (msg.startsWith("hourly limit without a key")) {
            kind = Wait.HOURLY_LIMIT;
            reason = "Hourly limit reached";
            fallback = Duration.ofSeconds(60);
        } else if (msg.startsWith("too many active jobs")) {
            kind = Wait.BUSY;
            reason = "Busy with other jobs from your address";
            fallback = Duration.ofSeconds(30);
        } else {
            kind = Wait.RATE_LIMIT;
            reason = "Rate limited by the server";
            fallback = Duration.ofSeconds(60);
        }
        Duration after = capped(e.retryAfter().map(RetryPolicy::atLeastASecond).orElse(fallback), poll);
        if (waitedOn429.plus(after).compareTo(RATE_LIMIT_BUDGET) > 0) {
            return new Fail("Rate limited by the server for over 70 minutes");
        }
        return new Retry(after, false, kind, reason);
    }

    private static Duration atLeastASecond(Duration d) {
        return d.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : d;
    }
}
