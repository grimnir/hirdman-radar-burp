package pro.hirdman.radar.menu;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class MenuModelTest {

    @Test
    void oneHostOffersParentsAndCheck() {
        MenuModel m = MenuModel.of(List.of("VPN.b.example.com."));
        assertEquals(List.of("b.example.com", "example.com"), m.findDomains());
        assertEquals(List.of("vpn.b.example.com"), m.checkHosts());
        assertEquals("Check vpn.b.example.com for leaks", m.checkLabel());
    }

    @Test
    void severalHostsMergeParents() {
        MenuModel m = MenuModel.of(List.of("a.example.com", "b.example.com", "x.other.org"));
        assertEquals(List.of("example.com", "other.org"), m.findDomains());
        assertEquals(List.of("a.example.com", "b.example.com", "x.other.org"), m.checkHosts());
        assertEquals("Check 3 selected hosts for leaks", m.checkLabel());
    }

    @Test
    void ipsAreDropped() {
        MenuModel m = MenuModel.of(List.of("10.0.0.1", "::1", "[::1]"));
        assertEquals(List.of(), m.findDomains());
        assertEquals(List.of(), m.checkHosts());
        assertNull(m.checkLabel());
    }

    @Test
    void invalidHostsAreDropped() {
        MenuModel m = MenuModel.of(Arrays.asList("_dmarc.example.com", "a b.example.com", null, ""));
        assertEquals(List.of(), m.findDomains());
        assertNull(m.checkLabel());
    }

    @Test
    void duplicatesCollapse() {
        MenuModel m = MenuModel.of(List.of("a.example.com", "A.EXAMPLE.COM"));
        assertEquals(List.of("a.example.com"), m.checkHosts());
        assertEquals(List.of("example.com"), m.findDomains());
        assertEquals("Check a.example.com for leaks", m.checkLabel());
    }

    @Test
    void apexHostOffersItself() {
        assertEquals(List.of("example.co.uk"), MenuModel.of(List.of("example.co.uk")).findDomains());
    }

    @Test
    void atMostEightDomains() {
        MenuModel m = MenuModel.of(IntStream.range(0, 10).mapToObj(i -> "www.d" + i + ".com").toList());
        assertEquals(IntStream.range(0, 8).mapToObj(i -> "d" + i + ".com").toList(), m.findDomains());
        assertEquals(10, m.checkHosts().size());
        assertEquals("Check 10 selected hosts for leaks", m.checkLabel());
    }
}
