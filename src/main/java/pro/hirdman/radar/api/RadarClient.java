package pro.hirdman.radar.api;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import pro.hirdman.radar.Version;

/** Radar API client; every request goes through the given transport and only to the configured server. */
public final class RadarClient implements Radar {

    private static final Duration META_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration SUBDOMAINS_TIMEOUT = Duration.ofSeconds(75);
    private static final Duration JOB_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration POLL_TIMEOUT = Duration.ofSeconds(30);
    // Job ids end up in URL paths, so only plain tokens are accepted.
    private static final Pattern JOB_ID = Pattern.compile("[A-Za-z0-9_-]{1,128}");

    private final ConnectionSettings settings;
    private final Transport transport;

    /** A client for the Server URL setting, or null when the setting is not a usable URL. */
    public static RadarClient of(String serverUrl, Transport transport) {
        try {
            return new RadarClient(ConnectionSettings.of(serverUrl), transport);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public RadarClient(ConnectionSettings settings, Transport transport) {
        this.settings = settings;
        this.transport = transport;
    }

    @Override
    public Meta meta() throws ApiException {
        Meta m = parse(send("GET", "/api/v1/meta", null, META_TIMEOUT), Meta.class);
        if (m.limits() == null || m.limits().maxHosts() < 1) {
            throw ApiException.malformed("no limits in /meta", null);
        }
        return m;
    }

    @Override
    public SubdomainList subdomains(String domain, boolean rescan) throws ApiException {
        String query = "?domain=" + URLEncoder.encode(domain, StandardCharsets.UTF_8) + (rescan ? "&rescan=true" : "");
        return parse(send("GET", "/api/v1/subdomains" + query, null, SUBDOMAINS_TIMEOUT), SubdomainList.class);
    }

    @Override
    public String startJob(JobRequest request) throws ApiException {
        Reply r = send("POST", "/api/v1/jobs", request.toJson(), JOB_TIMEOUT);
        JsonElement id = object(r).get("job_id");
        if (id == null || !id.isJsonPrimitive() || !JOB_ID.matcher(id.getAsString()).matches()) {
            throw ApiException.malformed("no usable job_id", null);
        }
        return id.getAsString();
    }

    @Override
    public JobPage poll(String jobId, int after) throws ApiException {
        return parse(send("GET", jobPath(jobId) + "?after=" + after, null, POLL_TIMEOUT), JobPage.class);
    }

    @Override
    public void deleteJob(String jobId, Duration timeout) throws ApiException {
        try {
            send("DELETE", jobPath(jobId), null, timeout);
        } catch (ApiException e) {
            if (e.status() != 404) {
                throw e;
            }
        }
    }

    private static String jobPath(String jobId) throws ApiException {
        if (jobId == null || !JOB_ID.matcher(jobId).matches()) {
            throw ApiException.malformed("bad job id", null);
        }
        return "/api/v1/jobs/" + jobId;
    }

    private Reply send(String method, String pathAndQuery, String body, Duration timeout) throws ApiException {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("User-Agent", "HirdmanRadar/" + Version.current());
        headers.put("Accept", "application/json");
        if (body != null) {
            headers.put("Content-Type", "application/json");
        }
        URI url = settings.server().resolve(pathAndQuery);
        Reply r;
        try {
            r = transport.send(method, url, headers, body, timeout);
        } catch (Transport.TooLarge e) {
            throw ApiException.malformed(e.getMessage(), null);
        } catch (IOException e) {
            throw ApiException.unreachable(e);
        }
        if (r.status() < 200 || r.status() > 299) {
            throw ApiException.http(r);
        }
        if (r.body().length() > Transport.MAX_BODY) {
            throw ApiException.malformed(Transport.TooLarge.MESSAGE, null);
        }
        return r;
    }

    private static <T> T parse(Reply r, Class<T> type) throws ApiException {
        JsonObject o = object(r);
        try {
            return Json.GSON.fromJson(o, type);
        } catch (RuntimeException e) {
            // Gson reports bad data with several unchecked types; all mean the same here.
            throw ApiException.malformed(e.getMessage(), e);
        }
    }

    private static JsonObject object(Reply r) throws ApiException {
        try {
            JsonElement e = JsonParser.parseString(r.body());
            if (e.isJsonObject()) {
                return e.getAsJsonObject();
            }
        } catch (RuntimeException e) {
            throw ApiException.malformed(e.getMessage(), e);
        }
        throw ApiException.malformed("answer is not a JSON object", null);
    }
}
