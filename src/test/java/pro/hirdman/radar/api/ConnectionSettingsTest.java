package pro.hirdman.radar.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ConnectionSettingsTest {

    static String problem(String url) {
        return assertThrows(IllegalArgumentException.class, () -> ConnectionSettings.of(url)).getMessage();
    }

    @Test
    void trimsTrailingSlash() {
        ConnectionSettings s = ConnectionSettings.of("  https://scan.hirdman.pro/ ");
        assertEquals("https://scan.hirdman.pro", s.server().toString());
        assertEquals("scan.hirdman.pro", s.host());
    }

    @Test
    void keepsPortAndLowerCasesHost() {
        assertEquals("https://scan.example.com:8443", ConnectionSettings.of("HTTPS://Scan.Example.com:8443").server().toString());
    }

    @Test
    void rejectsPlainHttpToRemoteHost() {
        assertEquals("Server URL must start with https://", problem("http://scan.hirdman.pro"));
        assertEquals("Server URL must start with https://", problem("ftp://scan.hirdman.pro"));
        assertEquals("Server URL must start with https://", problem("scan.hirdman.pro"));
    }

    @Test
    void allowsLocalHttp() {
        assertEquals("http://localhost:8080", ConnectionSettings.of("http://localhost:8080").server().toString());
        assertEquals("127.0.0.1", ConnectionSettings.of("http://127.0.0.1:8090").host());
        assertEquals("[::1]", ConnectionSettings.of("http://[::1]:8090").host());
    }

    @Test
    void rejectsPath() {
        assertEquals("Server URL must not contain a path", problem("https://scan.hirdman.pro/api"));
    }

    @Test
    void rejectsUserInfoQueryFragment() {
        assertEquals("Server URL is not valid", problem("https://u:p@scan.hirdman.pro"));
        assertEquals("Server URL is not valid", problem("https://scan.hirdman.pro?x=1"));
        assertEquals("Server URL is not valid", problem("https://scan.hirdman.pro#x"));
    }

    @Test
    void rejectsEmptyAndBroken() {
        assertEquals("Server URL is not valid", problem(""));
        assertEquals("Server URL is not valid", problem(null));
        assertEquals("Server URL is not valid", problem("https://"));
        assertEquals("Server URL is not valid", problem("https://scan hirdman.pro"));
    }
}
