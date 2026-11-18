package pro.hirdman.radar.api;

import com.google.gson.JsonElement;

/** One event of a server job, as a poll returns it. */
public record JobEvent(int seq, String event, JsonElement data) {
}
