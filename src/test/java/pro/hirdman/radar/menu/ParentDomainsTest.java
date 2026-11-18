package pro.hirdman.radar.menu;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

class ParentDomainsTest {

    @Test
    void parentsNearestFirst() {
        assertEquals(List.of("b.example.co.uk", "example.co.uk"), ParentDomains.parents("vpn.b.example.co.uk"));
        assertEquals(List.of("b.example.com", "example.com"), ParentDomains.parents("a.b.example.com"));
        assertEquals(List.of("example.com"), ParentDomains.parents("vpn.example.com"));
    }

    @Test
    void apexOffersItself() {
        assertEquals(List.of("example.com"), ParentDomains.parents("example.com"));
        assertEquals(List.of("example.co.uk"), ParentDomains.parents("example.co.uk"));
    }

    @Test
    void bareZoneOffersNothing() {
        assertEquals(List.of(), ParentDomains.parents("co.uk"));
        assertEquals(List.of(), ParentDomains.parents("com"));
    }

    @Test
    void baseIsRegistrable() {
        assertEquals("example.com", ParentDomains.base("a.b.example.com"));
        assertEquals("example.com.ru", ParentDomains.base("lk.example.com.ru"));
        assertEquals("example.com", ParentDomains.base("example.com"));
        assertEquals("co.uk", ParentDomains.base("co.uk"));
    }
}
