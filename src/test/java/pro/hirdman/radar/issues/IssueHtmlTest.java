package pro.hirdman.radar.issues;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
