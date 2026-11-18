package pro.hirdman.radar.api;

/** A known job event whose data cannot be read. */
public final class MalformedEventException extends Exception {

    private static final long serialVersionUID = 1L;

    MalformedEventException(JobEvent e, String reason) {
        super(Json.oneLine("Malformed " + e.event() + " event #" + e.seq() + ": " + reason));
    }
}
