package pro.hirdman.radar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class VersionTest {

    @Test
    void currentIsBuildVersion() {
        assertEquals("0.2.0", Version.current());
    }

    @Test
    void atLeastComparesNumbers() {
        assertTrue(Version.atLeast("0.10.0", "0.9.0"));
        assertFalse(Version.atLeast("0.1.0", "0.2.0"));
        assertTrue(Version.atLeast("0.1.0", "0.1.0"));
        assertFalse(Version.atLeast("0.9.9", "1.0.0"));
    }

    @Test
    void atLeastToleratesOddServerVersions() {
        assertTrue(Version.atLeast("0.1.0", "0.1.0-rc1"));
        assertTrue(Version.atLeast("0.1.0", "x"));
        assertFalse(Version.atLeast("0.1.0", "0.2"));
    }
}
