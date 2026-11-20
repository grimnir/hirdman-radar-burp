package pro.hirdman.radar.api;

import com.google.gson.JsonElement;
import org.jspecify.annotations.Nullable;

/** One event of a server job, as a poll returns it. */
public record JobEvent(int seq, String event, @Nullable JsonElement data) {
}
