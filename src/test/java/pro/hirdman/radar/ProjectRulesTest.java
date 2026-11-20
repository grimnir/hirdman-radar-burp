package pro.hirdman.radar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Product rules checked over the sources: no API key header, network only through Burp, Montoya kept in burp/. */
class ProjectRulesTest {

    private static final Path MAIN = Path.of("src", "main");
    private static final String PKG = "java/pro/hirdman/radar/";

    private static final Pattern API_KEY = Pattern.compile("x-api-key", Pattern.CASE_INSENSITIVE);
    // Requests go through Burp's HTTP stack (BurpTransport), never the JDK's.
    private static final Pattern JDK_NETWORK = Pattern.compile(
            "\\bjava\\.net\\.(http\\b|URLConnection\\b|HttpURLConnection\\b|Socket\\b|ServerSocket\\b|DatagramSocket\\b)"
                    + "|\\bjavax\\.net\\b|\\bHttpsURLConnection\\b");
    private static final Pattern MONTOYA = Pattern.compile("\\bburp\\.api\\.montoya\\b");

    // Montoya stays in burp/ and these classes; add a file here only when it cannot take a plain interface.
    private static final Set<String> MONTOYA_ALLOWED = Set.of(
            PKG + "HirdmanRadar.java",
            PKG + "config/ProjectSwitch.java",
            PKG + "ui/RadarTab.java");

    @Test
    void mainSourcesFollowTheRules() {
        List<String> found = new ArrayList<>();
        for (Path file : files(MAIN)) {
            String rel = MAIN.relativize(file).toString().replace('\\', '/');
            found.addAll(violations(rel, read(file)));
        }
        assertTrue(found.isEmpty(), String.join("\n", found));
    }

    @Test
    void catchesEachRuleWithFileAndLine() {
        String ui = PKG + "ui/HostView.java";
        assertEquals(List.of(ui + ":2: sends the X-API-Key header"),
                violations(ui, List.of("class A {", "String h = \"x-api-KEY\";")));
        assertEquals(List.of(ui + ":1: uses the JDK network stack instead of Burp's"),
                violations(ui, List.of("import java.net.http.HttpClient;")));
        assertEquals(List.of(ui + ":1: uses the JDK network stack instead of Burp's"),
                violations(ui, List.of("import java.net.Socket;")));
        assertEquals(List.of(ui + ":1: uses the Montoya API outside burp/ and the allowed classes"),
                violations(ui, List.of("import burp.api.montoya.MontoyaApi;")));
        assertEquals(List.of(PKG + "burp/BurpTransport.java:1: uses the JDK network stack instead of Burp's"),
                violations(PKG + "burp/BurpTransport.java", List.of("import java.net.HttpURLConnection;")));
        assertEquals(List.of(), violations(PKG + "burp/RadarMenu.java", List.of("import burp.api.montoya.MontoyaApi;")));
        assertEquals(List.of(), violations(PKG + "ui/RadarTab.java", List.of("import burp.api.montoya.MontoyaApi;")));
        assertEquals(List.of(), violations(ui, List.of("import java.net.URI;", "import java.net.URLEncoder;")));
    }

    private static List<String> violations(String rel, List<String> lines) {
        boolean java = rel.endsWith(".java");
        boolean montoyaAllowed = rel.startsWith(PKG + "burp/") || MONTOYA_ALLOWED.contains(rel);
        List<String> found = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String at = rel + ":" + (i + 1) + ": ";
            if (API_KEY.matcher(line).find()) {
                found.add(at + "sends the X-API-Key header");
            }
            if (java && JDK_NETWORK.matcher(line).find()) {
                found.add(at + "uses the JDK network stack instead of Burp's");
            }
            if (java && !montoyaAllowed && MONTOYA.matcher(line).find()) {
                found.add(at + "uses the Montoya API outside burp/ and the allowed classes");
            }
        }
        return found;
    }

    private static List<Path> files(Path root) {
        assertTrue(Files.isDirectory(root), "run from the project directory: " + root.toAbsolutePath());
        try (Stream<Path> all = Files.walk(root)) {
            return all.filter(Files::isRegularFile).sorted().toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static List<String> read(Path file) {
        try {
            return Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(file.toString(), e);
        }
    }
}
