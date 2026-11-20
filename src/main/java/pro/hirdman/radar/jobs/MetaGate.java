package pro.hirdman.radar.jobs;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;
import pro.hirdman.radar.api.Meta;

/** Remembers the last /meta answer and for which server, so it is asked once per Server URL. */
public final class MetaGate {

    private @Nullable URI server;
    private @Nullable Meta meta;
    private final List<BiConsumer<URI, Meta>> listeners = new CopyOnWriteArrayList<>();

    public synchronized boolean needsCheck(URI s) {
        return meta == null || !s.equals(server);
    }

    public void passed(URI s, Meta m) {
        synchronized (this) {
            server = s;
            meta = m;
        }
        listeners.forEach(l -> l.accept(s, m));
    }

    public synchronized Optional<Meta> last() {
        return Optional.ofNullable(meta);
    }

    /** The last answer when it came from {@code s}, read at once with its server. */
    public synchronized Optional<Meta> lastFor(URI s) {
        return s.equals(server) ? Optional.ofNullable(meta) : Optional.empty();
    }

    public void addListener(Consumer<Meta> onMeta) {
        listeners.add((s, m) -> onMeta.accept(m));
    }

    /** Also gets the server the answer came from. */
    public void addServerListener(BiConsumer<URI, Meta> onMeta) {
        listeners.add(onMeta);
    }
}
