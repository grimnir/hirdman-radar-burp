package pro.hirdman.radar.ui;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.JobPage;
import pro.hirdman.radar.api.JobRequest;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.SubdomainList;

/** A radar that only answers /meta: with {@link #answer}, or by throwing it when it is an exception. */
final class TestRadar implements Radar {

    static final Meta META = new Meta(1, "0.1.0", "anonymous", new Meta.Limits(50, 1.5, 300),
            new Meta.Notes("db", "cov", "Counts only, from the server."));
    static final String LIMITS = "Without a key: up to 50 hosts per check and 300 hosts per hour from your address.";

    final AtomicInteger metaCalls = new AtomicInteger();
    final AtomicReference<Object> answer = new AtomicReference<>(META);

    @Override
    public Meta meta() throws ApiException {
        metaCalls.incrementAndGet();
        Object a = answer.get();
        if (a instanceof ApiException e) {
            throw e;
        }
        if (a instanceof RuntimeException e) {
            throw e;
        }
        return (Meta) a;
    }

    @Override
    public SubdomainList subdomains(String domain, boolean rescan) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String startJob(JobRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public JobPage poll(String jobId, int after) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteJob(String jobId, Duration timeout) {
        throw new UnsupportedOperationException();
    }
}
