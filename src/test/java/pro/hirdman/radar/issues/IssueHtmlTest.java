package pro.hirdman.radar.issues;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class IssueHtmlTest {

    static int count(String s, String part) {
        int n = 0;
        for (int i = s.indexOf(part); i >= 0; i = s.indexOf(part, i + 1)) {
            n++;
        }
        return n;
    }

    @Test
    void deepNestingIsCutToText() {
        // Swing's HTML views recurse per level: 2400 nested lists overflowed the stack in Burp's issue pane.
        String deep = "<ul>".repeat(2400) + "x" + "</ul>".repeat(2400);
        String out = IssueHtml.clean(deep);
        assertEquals(IssueHtml.MAX_DEPTH, count(out, "<ul>"));
        assertEquals(IssueHtml.MAX_DEPTH, count(out, "</ul>"));
        assertTrue(out.startsWith("<ul>".repeat(IssueHtml.MAX_DEPTH) + "&lt;ul&gt;"), out.substring(0, 80));
        assertEquals("<p><b><i>x</i></b></p>", IssueHtml.clean("<p><b><i>x</i></b></p>"));
        assertEquals("<ul><li><b>a</b><br><i>b</i></li><li><a href=\"https://cwe.mitre.org/\">c</a></li></ul>",
                IssueHtml.clean("<ul><li><b>a</b><br><i>b</i></li><li><a href=\"https://cwe.mitre.org/\">c</a></li></ul>"));
    }

    @Test
    void onlyPlainNamedEntitiesStay() {
        assertEquals("&amp; &lt; &gt; &quot; &nbsp; &#39;", IssueHtml.clean("&amp; &lt; &gt; &quot; &nbsp; &#39;"));
        assertEquals("&amp;copy; &amp;AMP; &amp;lt", IssueHtml.clean("&copy; &AMP; &lt"));
    }

    @Test
    void numericEntitiesGetTheRawCharacterRules() {
        // Bidi and control characters are dropped whether they come raw or as an entity.
        assertEquals("xy", IssueHtml.clean("&#x202E;x&#0;&#8203;y&#X202e;"));
        assertEquals("&lt;script&gt;&quot;&#39;&amp;", IssueHtml.clean("&#60;script&#x3E;&#34;&#39;&#38;"));
        assertEquals("\u2022 \uD83D\uDE00\n", IssueHtml.clean("&#8226; &#x1F600;&#10;"));
        assertEquals("", IssueHtml.clean("&#1114112;&#xD800;&#xDFFF;"));
    }

    @Test
    void supplementaryFormatCharactersAndLoneSurrogatesAreDropped() {
        assertEquals("ab\uD83D\uDE00", IssueHtml.clean("a\uDB40\uDC01b\uD800\uD83D\uDE00\uDC00"));
    }

    @Test
    void linksGoOnlyToKnownReferenceSitesAndTheServer() {
        for (String host : new String[] {"cwe.mitre.org", "capec.mitre.org", "attack.mitre.org", "owasp.org", "www.owasp.org",
                "cheatsheetseries.owasp.org", "hirdman.pro", "www.hirdman.pro", "www.cisa.gov", "pages.nist.gov", "CWE.MITRE.ORG"}) {
            String a = "<a href=\"https://" + host + "/x\">l</a>";
            assertEquals(a, IssueHtml.clean(a), host);
        }
        for (String host : new String[] {"evil.example", "1.2.3.4", "cwe.mitre.org.evil.example", "evil-owasp.org", "mitre.org",
                "x.hirdman.pro", "radar.example.com"}) {
            assertEquals("&lt;a href=&quot;https://" + host + "/&quot;&gt;l&lt;/a&gt;",
                    IssueHtml.clean("<a href=\"https://" + host + "/\">l</a>"), host);
        }
        assertEquals("<a href=\"https://Radar.example.com/x\">l</a>",
                IssueHtml.clean("<a href=\"https://Radar.example.com/x\">l</a>", "radar.example.com"));
    }

    static final String ALPHABET = "<>/\"'&;#abcdefghijklmnopqrstuvwxyz0123456789 \n\u0000\u202E\u2066";
    static final List<String> TOKENS = List.of("<p>", "</p>", "<b>", "</b>", "<i>", "</i>", "<ul>", "</ul>", "<ol>", "</ol>", "<li>",
            "</li>", "<br>", "<a href=\"https://owasp.org/x\">", "<a href=\"https://evil.example/\">", "</a>", "<script>", "<B>",
            "&amp;", "&nbsp;", "&copy;", "&#x202E;", "&#0;", "&#60;", "&#x3c;", "&#1114112;", "&#xD800;", "\uD83D\uDE00", "\uDB40\uDC01");
    static final Pattern OPENER = Pattern.compile("<(p|b|i|ul|ol|li)>|<a href=\"https://owasp\\.org/x\">");
    static final Pattern CLOSER = Pattern.compile("</(p|b|i|ul|ol|li|a)>");
    static final Pattern ENTITY = Pattern.compile("&(?:amp|lt|gt|quot|nbsp|#39);");

    @Test
    void randomInputComesOutAsSafeBalancedHtml() {
        Random random = new Random(75);
        for (int n = 0; n < 5000; n++) {
            StringBuilder in = new StringBuilder();
            for (int len = random.nextInt(300); in.length() < len; ) {
                if (random.nextInt(10) < 3) {
                    in.append(TOKENS.get(random.nextInt(TOKENS.size())));
                } else {
                    in.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
                }
            }
            String input = in.toString();
            String problem = problem(IssueHtml.clean(input));
            assertEquals(null, problem, () -> "input: " + input);
        }
    }

    @Test
    void theCheckerCatchesBadOutput() {
        for (String bad : new String[] {"<ul>", "</b>", "<b><i></b></i>", "<img>", "&#x202E;", "&copy;", "a\u202Eb", "a\u0000",
                "\"", ">", "<a href=\"https://evil.example/\"></a>", "<ul>".repeat(IssueHtml.MAX_DEPTH + 1)}) {
            assertTrue(problem(bad) != null, bad);
        }
        assertEquals(null, problem("<p>a &amp; <b>b</b><br></p>\n\uD83D\uDE00"));
    }

    /** What is wrong with the output, or null: only listed tags, all closed in order, depth capped, plain text otherwise. */
    static String problem(String out) {
        Deque<String> open = new ArrayDeque<>();
        int i = 0;
        while (i < out.length()) {
            int c = out.codePointAt(i);
            if (c == '<') {
                Matcher opener = OPENER.matcher(out).region(i, out.length());
                Matcher closer = CLOSER.matcher(out).region(i, out.length());
                if (out.startsWith("<br>", i)) {
                    i += 4;
                } else if (opener.lookingAt()) {
                    open.push(opener.group(1) == null ? "a" : opener.group(1));
                    if (open.size() > IssueHtml.MAX_DEPTH) {
                        return "too deep at " + i;
                    }
                    i = opener.end();
                } else if (closer.lookingAt()) {
                    if (open.isEmpty() || !open.pop().equals(closer.group(1))) {
                        return "unmatched closer at " + i;
                    }
                    i = closer.end();
                } else {
                    return "tag not allowed at " + i;
                }
                continue;
            }
            if (c == '&') {
                Matcher entity = ENTITY.matcher(out).region(i, out.length());
                if (!entity.lookingAt()) {
                    return "entity not allowed at " + i;
                }
                i = entity.end();
                continue;
            }
            int type = Character.getType(c);
            if (c == '>' || c == '"' || c == '\'' || type == Character.FORMAT || type == Character.SURROGATE
                    || Character.isISOControl(c) && c != '\n') {
                return "raw character U+" + Integer.toHexString(c) + " at " + i;
            }
            i += Character.charCount(c);
        }
        return open.isEmpty() ? null : "left open: " + open;
    }
}
