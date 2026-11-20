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
}
