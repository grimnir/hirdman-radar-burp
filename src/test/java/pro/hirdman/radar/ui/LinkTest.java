package pro.hirdman.radar.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LinkTest {

    static final String UTM = "utm_source=burp&utm_medium=plugin&utm_content=footer";

    @Test
    void hirdmanLinksGetSourceTags() {
        assertEquals("https://hirdman.pro/?" + UTM, Link.tagged("https://hirdman.pro"));
        assertEquals("https://hirdman.pro/x?" + UTM, Link.tagged("https://hirdman.pro/x"));
        assertEquals("https://scan.hirdman.pro/?domain=a.com&" + UTM, Link.tagged("https://scan.hirdman.pro/?domain=a.com"));
        assertEquals("https://hirdman.pro/?" + UTM, RadarTab.SITE_LINK);
    }

    @Test
    void otherSitesAndOddLinksStayAsTheyAre() {
        String gh = "https://github.com/grimnir/hirdman-radar-burp/releases/latest";
        assertEquals(gh, Link.tagged(gh));
        assertEquals("https://nothirdman.pro/", Link.tagged("https://nothirdman.pro/"));
        assertEquals("https://hirdman.pro/#a", Link.tagged("https://hirdman.pro/#a"));
        assertEquals("not a url", Link.tagged("not a url"));
    }

    @Test
    void theLinkIsPlainTextAndFocusable() {
        Link l = new Link("<html>x");
        assertEquals(Boolean.TRUE, l.getClientProperty("html.disable"));
        assertTrue(l.isFocusable());
    }
}
