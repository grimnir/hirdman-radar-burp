package pro.hirdman.radar.api;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.util.List;
import java.util.Objects;

/** Shared JSON settings and helpers for server data. */
public final class Json {

    public static final Gson GSON = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .disableHtmlEscaping()
            .create();

    static final int MAX_TEXT = 300;

    private Json() {
    }

    /** Server text made safe for one-line display: control, format and space runs become one space, 300 chars max. */
    public static String oneLine(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder b = new StringBuilder(Math.min(s.length(), MAX_TEXT));
        boolean gap = false;
        for (int i = 0; i < s.length() && b.length() < MAX_TEXT; i++) {
            char c = s.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c) || Character.isSpaceChar(c)
                    || Character.getType(c) == Character.FORMAT) {
                gap = b.length() > 0;
                continue;
            }
            if (gap) {
                b.append(' ');
                gap = false;
                if (b.length() == MAX_TEXT) {
                    break;
                }
            }
            b.append(c);
        }
        int end = b.length();
        if (end > 0 && (b.charAt(end - 1) == ' ' || Character.isHighSurrogate(b.charAt(end - 1)))) {
            b.setLength(end - 1);
        }
        return b.toString();
    }

    /** The JVM's one copy of a text many rows repeat (finding texts, source names); null stays null. */
    static String shared(String s) {
        return s == null ? null : s.intern();
    }

    /** Immutable copy without nulls; a missing list becomes empty. */
    static <T> List<T> list(List<T> items) {
        return items == null ? List.of() : items.stream().filter(Objects::nonNull).toList();
    }
}
