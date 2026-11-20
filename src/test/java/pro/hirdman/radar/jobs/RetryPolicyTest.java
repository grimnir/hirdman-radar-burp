package pro.hirdman.radar.jobs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.Reply;
import pro.hirdman.radar.jobs.RetryPolicy.Decision;
import pro.hirdman.radar.jobs.RetryPolicy.Fail;
import pro.hirdman.radar.jobs.RetryPolicy.Retry;
import pro.hirdman.radar.jobs.RetryPolicy.Wait;

class RetryPolicyTest {

    static final String HOST = "scan.hirdman.pro";
    static final String OFFLINE = "Cannot reach scan.hirdman.pro. The plugin needs internet access, directly or through Burp's upstream proxy. Behind a proxy that re-signs HTTPS, turn off the certificate check in Settings > Extensions > Hirdman Radar.";

    static ApiException unreachable() {
        return ApiException.unreachable(new IOException("Connection refused"));
    }

    static ApiException http(int status, String body, String... headers) {
        Map<String, String> h = headers.length == 2 ? Map.of(headers[0], headers[1]) : Map.of();
        return ApiException.http(new Reply(status, h, body));
    }

    static Decision decide(ApiException e, int used, int max, Duration waited429, double random) {
        return RetryPolicy.decide(e, used, max, waited429, HOST, () -> random, false);
    }

    static Decision decidePoll(ApiException e, int used, int max) {
        return RetryPolicy.decide(e, used, max, Duration.ZERO, HOST, () -> 0.5, true);
    }

    static Decision decide(ApiException e, int used) {
        return decide(e, used, 5, Duration.ZERO, 0.5);
    }

    @Test
    void backoffSequence() {
        int[] expected = {2, 4, 8, 16, 30, 30, 30, 30, 30, 30};
        for (int used = 0; used < expected.length; used++) {
            Retry r = (Retry) decide(unreachable(), used, 20, Duration.ZERO, 0.5);
            assertEquals(Duration.ofSeconds(expected[used]), r.after(), "attemptsUsed " + used);
            assertEquals(Wait.BACKOFF, r.kind());
            assertEquals(true, r.countsAsAttempt());
            assertEquals("Server unreachable", r.reason());
        }
    }

    @Test
    void jitterBounds() {
        assertEquals(Duration.ofMillis(1600), ((Retry) decide(unreachable(), 0, 5, Duration.ZERO, 0.0)).after());
        assertEquals(Duration.ofMillis(2400), ((Retry) decide(unreachable(), 0, 5, Duration.ZERO, 1.0)).after());
    }

    @Test
    void exhaustedUnreachableFails() {
        assertEquals(new Fail(OFFLINE), decide(unreachable(), 5, 5, Duration.ZERO, 0.5));
        // The fifth failed try is the last one: four pauses, then Failed.
        assertEquals(new Fail(OFFLINE), decide(unreachable(), 4, 5, Duration.ZERO, 0.5));
        assertEquals(Wait.BACKOFF, ((Retry) decide(unreachable(), 3, 5, Duration.ZERO, 0.5)).kind());
    }

    @Test
    void gatewayCodesRetryAndThenFail() {
        for (int code : new int[] {500, 502, 503, 504, 520, 521, 522, 523, 524}) {
            Retry r = (Retry) decide(http(code, "<html>bad gateway</html>"), 0);
            assertEquals("Server unavailable (HTTP " + code + ")", r.reason());
            assertEquals(new Fail("Server unavailable (HTTP " + code + ")"), decide(http(code, ""), 4));
        }
    }

    @Test
    void http503UsesRetryAfter() {
        assertEquals(new Retry(Duration.ofSeconds(30), true, Wait.BACKOFF, "Server unavailable (HTTP 503)"),
                decide(http(503, "{\"error\":\"server is busy, try again later\"}", "Retry-After", "30"), 0));
    }

    @Test
    void backoffRetryAfterIsCappedAtTwoMinutes() {
        assertEquals(Duration.ofSeconds(120), ((Retry) decide(http(503, "", "Retry-After", "900"), 0)).after());
    }

    @Test
    void hourlyLimitWaitsRetryAfter() {
        ApiException e = http(429, "{\"error\":\"hourly limit without a key: 300 hosts per hour\"}", "Retry-After", "2400");
        assertEquals(new Retry(Duration.ofSeconds(2400), false, Wait.HOURLY_LIMIT, "Hourly limit reached"),
                decide(e, 4));
    }

    @Test
    void busyWaitsThirtySeconds() {
        ApiException e = http(429, "{\"error\":\"too many active jobs from this address (max 2)\"}");
        assertEquals(new Retry(Duration.ofSeconds(30), false, Wait.BUSY, "Busy with other jobs from your address"),
                decide(e, 0));
    }

    @Test
    void otherRateLimitWaitsRetryAfterOrSixtySeconds() {
        assertEquals(new Retry(Duration.ofSeconds(60), false, Wait.RATE_LIMIT, "Rate limited by the server"),
                decide(http(429, "{\"error\":\"rate limit exceeded\"}"), 0));
        assertEquals(Duration.ofSeconds(9), ((Retry) decide(http(429, "", "Retry-After", "9"), 0)).after());
    }

    @Test
    void aZeroRetryAfterWaitsOneSecond() {
        // The server can send 0; without a floor the job retried in a tight loop and the 429 budget never grew.
        assertEquals(Duration.ofSeconds(1), ((Retry) decide(http(429, "", "Retry-After", "0"), 0)).after());
        assertEquals(Duration.ofSeconds(1), ((Retry) decide(http(503, "", "Retry-After", "0"), 0)).after());
    }

    @Test
    void http429BudgetIsSeventyMinutes() {
        ApiException e = http(429, "{}", "Retry-After", "120");
        assertEquals(new Fail("Rate limited by the server for over 70 minutes"),
                decide(e, 0, 5, Duration.ofMinutes(69), 0.5));
        assertEquals(Wait.RATE_LIMIT, ((Retry) decide(e, 0, 5, Duration.ofMinutes(68), 0.5)).kind());
    }

    @Test
    void http401Fails() {
        assertEquals(new Fail("The radar server is not taking checks right now. Try again later."),
                decide(http(401, "{\"error\":\"unauthorized\"}"), 0));
    }

    @Test
    void http400ShowsServerText() {
        assertEquals(new Fail("invalid host: a b"), decide(http(400, "{\"error\":\"invalid host: a b\"}"), 0));
    }

    @Test
    void otherStatusesFailWithTheCode() {
        assertEquals(new Fail("HTTP 302"), decide(http(302, ""), 0));
        assertEquals(new Fail("HTTP 413"), decide(http(413, "Request Entity Too Large"), 0));
    }

    @Test
    void malformedFails() {
        assertEquals(new Fail("Unexpected answer from the server"), decide(ApiException.malformed("x", null), 0));
    }

    @Test
    void aPollWaitsAtMostFortyFiveSeconds() {
        // The server cancels a job nobody polls for 60 s.
        assertEquals(Duration.ofSeconds(45), ((Retry) decidePoll(http(503, "", "Retry-After", "900"), 0, 5)).after());
        assertEquals(Duration.ofSeconds(45), ((Retry) decidePoll(http(429, "", "Retry-After", "3600"), 0, 5)).after());
        assertEquals(new Retry(Duration.ofSeconds(45), false, Wait.HOURLY_LIMIT, "Hourly limit reached"),
                decidePoll(http(429, "{\"error\":\"hourly limit without a key: 300 hosts per hour\"}"), 0, 5));
        assertEquals(Duration.ofSeconds(9), ((Retry) decidePoll(http(429, "", "Retry-After", "9"), 0, 5)).after());
    }

    @Test
    void aMalformedPollIsTriedThreeTimesAtMost() {
        ApiException e = ApiException.malformed("x", null);
        Retry r = (Retry) decidePoll(e, 0, 5);
        assertEquals(new Retry(Duration.ofSeconds(2), true, Wait.BACKOFF, "Unexpected answer from the server"), r);
        assertEquals(Wait.BACKOFF, ((Retry) decidePoll(e, 1, 5)).kind());
        assertEquals(new Fail("Unexpected answer from the server"), decidePoll(e, 2, 5));
        assertEquals(new Fail("Unexpected answer from the server"), decidePoll(e, 1, 2));
    }

    @Test
    void malformedFailsOutsidePolls() {
        assertEquals(new Fail("Unexpected answer from the server"), decide(ApiException.malformed("x", null), 0, 5, Duration.ZERO, 0.5));
    }

    @Test
    void aBlockedRequestFailsWithItsReasonEvenOnAPoll() {
        // Sending again would send the added headers again.
        ApiException e = ApiException.blocked("Burp added credentials to the radar request (Cookie).");
        assertEquals(new Fail("Burp added credentials to the radar request (Cookie)."), decide(e, 0));
        assertEquals(new Fail("Burp added credentials to the radar request (Cookie)."), decidePoll(e, 0, 5));
    }
}
