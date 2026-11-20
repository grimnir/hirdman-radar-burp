package pro.hirdman.radar.issues;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Server HTML for issue fields, cut down to bare formatting tags and plain https links (references);
 * everything else is shown as text.
 */
final class IssueHtml {

    static final int MAX_LENGTH = 10_000;
    /** Deeper tags are text: Swing's HTML views recurse per level and overflow the stack on deep nesting. */
    static final int MAX_DEPTH = 6;
    private static final List<String> TAGS = List.of("p", "b", "i", "ul", "ol", "li");
    // Only the exact form the server writes: https, no attributes but href, no quotes, spaces or & in the address.
    private static final Pattern LINK = Pattern.compile("<a href=\"https://[A-Za-z0-9.-]{1,253}(?:/[A-Za-z0-9._~!$()*+,;=:@%/?#-]{0,300})?\">");
    private static final Pattern ENTITY = Pattern.compile("&(?:[a-zA-Z][a-zA-Z0-9]{1,30}|#[0-9]{1,7}|#x[0-9a-fA-F]{1,6});");

    private IssueHtml() {
    }

    static String clean(String html) {
        if (html == null) {
            return "";
        }
        String s = html.length() > MAX_LENGTH ? html.substring(0, MAX_LENGTH) : html;
        StringBuilder out = new StringBuilder(s.length());
        var entity = ENTITY.matcher(s);
        var link = LINK.matcher(s);
        // Open tags, innermost first: a closer shuts everything inside it, the rest is shut at the end.
        Deque<String> open = new ArrayDeque<>();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '<') {
                int end = tag(s, i, link, open, out);
                if (end > i) {
                    i = end;
                    continue;
                }
            }
            if (c == '&' && entity.region(i, s.length()).lookingAt()) {
                out.append(entity.group());
                i = entity.end();
                continue;
            }
            switch (c) {
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '&' -> out.append("&amp;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> {
                    boolean control = Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t';
                    if (!control && Character.getType(c) != Character.FORMAT) {
                        out.append(c);
                    }
                }
            }
            i++;
        }
        while (!open.isEmpty()) {
            out.append("</").append(open.pop()).append('>');
        }
        return out.toString();
    }

    /** Plain text for HTML element content (never an attribute): markup characters escaped, entities included. */
    static String text(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Writes the allowed tag at i and returns the index after it; returns i when there is none. */
    private static int tag(String s, int i, Matcher link, Deque<String> open, StringBuilder out) {
        if (s.startsWith("<br>", i)) {
            out.append("<br>");
            return i + 4;
        }
        if (open.size() < MAX_DEPTH) {
            for (String tag : TAGS) {
                String opener = "<" + tag + ">";
                if (s.startsWith(opener, i)) {
                    out.append(opener);
                    open.push(tag);
                    return i + opener.length();
                }
            }
            if (!open.contains("a") && link.region(i, s.length()).lookingAt()) {
                out.append(link.group());
                open.push("a");
                return link.end();
            }
        }
        // Only an open tag can be closed.
        Optional<String> closed = open.stream().filter(t -> s.startsWith("</" + t + ">", i)).findFirst();
        if (closed.isPresent()) {
            closeTo(closed.get(), open, out);
            return i + closed.get().length() + 3;
        }
        return i;
    }

    private static void closeTo(String tag, Deque<String> open, StringBuilder out) {
        String t;
        do {
            t = open.pop();
            out.append("</").append(t).append('>');
        } while (!t.equals(tag));
    }
}
