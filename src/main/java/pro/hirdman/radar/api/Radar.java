package pro.hirdman.radar.api;

import java.time.Duration;

/** The radar server's /api/v1 as the plugin uses it. */
public interface Radar {

    Meta meta() throws ApiException;

    SubdomainList subdomains(String domain, boolean rescan) throws ApiException;

    /** Starts a server job and returns its id. */
    String startJob(JobRequest request) throws ApiException;

    /** Events after {@code after}; the server waits up to 20 s for a new one. */
    JobPage poll(String jobId, int after) throws ApiException;

    /** Cancels a server job; a job that is already gone counts as cancelled. */
    void deleteJob(String jobId, Duration timeout) throws ApiException;
}
