package pro.hirdman.radar.jobs;

import com.google.gson.JsonParser;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import pro.hirdman.radar.api.ApiException;
import pro.hirdman.radar.api.JobEvent;
import pro.hirdman.radar.api.JobPage;
import pro.hirdman.radar.api.JobRequest;
import pro.hirdman.radar.api.Meta;
import pro.hirdman.radar.api.Radar;
import pro.hirdman.radar.api.Reply;
import pro.hirdman.radar.api.SubdomainList;

/** Scripted radar: each method answers from its own queue and every call is recorded. */
final class FakeRadar implements Radar {

    static final Meta META = new Meta(1, "0.1.0", "anonymous", new Meta.Limits(50, 1.5, 300),
            new Meta.Notes("db", "coverage", "Counts only: no accounts, passwords, raw records or dumps."));

    /** A poll that blocks until {@code release} opens, then answers {@code page}. */
    record Hang(CountDownLatch release, JobPage page) {
    }

    final Deque<Object> metas = new ArrayDeque<>();
    final Deque<Object> subdomains = new ArrayDeque<>();
    final Deque<Object> starts = new ArrayDeque<>();
    final Deque<Object> polls = new ArrayDeque<>();
    final List<String> calls = new CopyOnWriteArrayList<>();
    final List<JobRequest> started = new CopyOnWriteArrayList<>();
    final List<Integer> pollAfters = new CopyOnWriteArrayList<>();
    final List<String> deleted = new CopyOnWriteArrayList<>();
    private int jobIds;

    // Answer helpers.

    static ApiException unreachable() {
        return ApiException.unreachable(new IOException("Connection refused"));
    }

    static ApiException http(int status, String body, String... headers) {
        Map<String, String> h = headers.length == 2 ? Map.of(headers[0], headers[1]) : Map.of();
        return ApiException.http(new Reply(status, h, body));
    }

    static JobEvent ev(String name, String data) {
        return new JobEvent(0, name, JsonParser.parseString(data));
    }

    static JobEvent check(String host, boolean checked, String... findingSeverities) {
        StringBuilder f = new StringBuilder();
        for (String s : findingSeverities) {
            f.append(f.isEmpty() ? "" : ",").append("{\"kind\":\"stealer_logs\",\"severity\":\"").append(s)
                    .append("\",\"confidence\":\"tentative\",\"name\":\"Infostealer records linked to host\",\"detail\":\"d\",\"background\":\"b\",\"remediation\":\"r\"}");
        }
        return ev("subdomain_check", "{\"domain\":\"" + host + "\",\"stealer_count\":" + findingSeverities.length
                + ",\"hc_checked\":" + checked + ",\"findings\":[" + f + "]}");
    }

    static JobEvent rootCheck(String host) {
        return ev("domain_check", "{\"domain\":\"" + host + "\",\"hc_checked\":true,\"findings\":[]}");
    }

    static JobEvent done(int total, int unchecked) {
        return ev("done", "{\"total_subdomains\":" + total + ",\"unchecked_hosts\":" + unchecked + "}");
    }

    static JobEvent error(String message) {
        return ev("error", "{\"message\":\"" + message + "\",\"recoverable\":false}");
    }

    static JobPage page(int next, boolean done, JobEvent... events) {
        return new JobPage(List.of(events), next, done);
    }

    // Radar.

    @Override
    public Meta meta() throws ApiException {
        calls.add("meta");
        return (Meta) answer(metas, META);
    }

    @Override
    public SubdomainList subdomains(String domain, boolean rescan) throws ApiException {
        calls.add("subdomains " + domain + " " + rescan);
        return (SubdomainList) answer(subdomains, null);
    }

    @Override
    public String startJob(JobRequest request) throws ApiException {
        calls.add("start " + request.toJson());
        started.add(request);
        String fallback;
        synchronized (this) {
            fallback = "j" + (++jobIds);
        }
        return (String) answer(starts, fallback);
    }

    @Override
    public JobPage poll(String jobId, int after) throws ApiException {
        calls.add("poll " + jobId + " " + after);
        pollAfters.add(after);
        Object a;
        synchronized (this) {
            a = polls.poll();
        }
        if (a instanceof Hang h) {
            try {
                h.release().await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                calls.add("interrupted");
                Thread.currentThread().interrupt();
            }
            return h.page();
        }
        if (a == null) {
            throw new IllegalStateException("no scripted poll");
        }
        return (JobPage) unwrap(a);
    }

    @Override
    public void deleteJob(String jobId, Duration timeout) {
        calls.add("delete " + jobId);
        deleted.add(jobId);
    }

    private synchronized Object answer(Deque<Object> q, Object fallback) throws ApiException {
        Object a = q.poll();
        if (a == null) {
            if (fallback == null) {
                throw new IllegalStateException("no scripted answer");
            }
            return fallback;
        }
        return unwrap(a);
    }

    private static Object unwrap(Object a) throws ApiException {
        if (a instanceof ApiException e) {
            throw e;
        }
        return a;
    }
}
