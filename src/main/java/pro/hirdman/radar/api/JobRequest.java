package pro.hirdman.radar.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.List;
import java.util.Objects;

/** Body of POST /api/v1/jobs: a domain scan or a host check, never both. */
public record JobRequest(String domain, boolean rescan, List<String> hosts) {

    public JobRequest {
        hosts = hosts == null ? null : List.copyOf(hosts);
    }

    public static JobRequest ofDomain(String domain, boolean rescan) {
        return new JobRequest(Objects.requireNonNull(domain), rescan, null);
    }

    public static JobRequest ofHosts(List<String> hosts) {
        return new JobRequest(null, false, Objects.requireNonNull(hosts));
    }

    public String toJson() {
        JsonObject o = new JsonObject();
        if (domain != null) {
            o.addProperty("domain", domain);
            o.addProperty("rescan", rescan);
        } else {
            JsonArray list = new JsonArray();
            hosts.forEach(list::add);
            o.add("hosts", list);
        }
        return Json.GSON.toJson(o);
    }
}
