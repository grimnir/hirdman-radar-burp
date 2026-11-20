package pro.hirdman.radar.burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.hirdman.radar.burp.Fakes.fake;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import java.awt.Component;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;
import javax.swing.JComponent;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import pro.hirdman.radar.api.ServerEvent.Check;
import pro.hirdman.radar.jobs.Job;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.jobs.JobRunner;
import pro.hirdman.radar.jobs.MetaGate;
import pro.hirdman.radar.jobs.Sleeper;
import pro.hirdman.radar.model.ResultStore;
import pro.hirdman.radar.ui.SendConfirm;

class RadarMenuTest {

    // An invalid server makes every job fail at once, so clicks never reach the network.
    final ResultStore store = new ResultStore();
    final JobRunner runner = new JobRunner(() -> null, store, new MetaGate(), Sleeper.real(),
            () -> new JobRunner.RunOptions(null, "test", false, 5, true), e -> { }, e -> { });
    final JobQueue queue = new JobQueue(runner, () -> null, j -> { });
    final JPanel tab = new JPanel();
    final List<String> asked = new ArrayList<>();
    boolean agree;
    final SendConfirm confirm = q -> {
        asked.add(q);
        return agree;
    };

    @AfterEach
    void tearDown() {
        queue.shutdown();
    }

    @Test
    void checkingMoreHostsThanOneServerCheckAsksFirst() {
        String[] hosts = IntStream.range(0, 51).mapToObj(i -> "h" + i + ".example.com").toArray(String[]::new);
        find(menu(hosts), "Check 51 selected hosts for leaks").doClick(0);
        assertEquals(List.of("Send 51 host names to the Hirdman Radar server for a leak check?"), asked);
        assertTrue(queue.jobs().isEmpty());
        agree = true;
        find(menu(hosts), "Check 51 selected hosts for leaks").doClick(0);
        assertEquals(51, queue.jobs().get(0).hosts().size());
        asked.clear();
        agree = false;
        find(menu(Arrays.copyOf(hosts, 50)), "Check 50 selected hosts for leaks").doClick(0);
        assertTrue(asked.isEmpty());
        assertEquals(2, queue.jobs().size());
    }

    @Test
    void theQuestionCountsOnlyHostsThatWillBeSent() {
        String[] hosts = IntStream.range(0, 80).mapToObj(i -> "h" + i + ".example.com").toArray(String[]::new);
        for (int i = 0; i < 20; i++) {
            store.apply("example.com", new Check(false, hosts[i], 0, 0, 0, 0, 0, true, List.of()), Instant.now());
        }
        find(menu(hosts), "Check 80 selected hosts for leaks").doClick(0);
        assertEquals(List.of("Send 60 host names to the Hirdman Radar server for a leak check?"), asked);
        assertTrue(queue.jobs().isEmpty());
    }

    static HttpRequestResponse rr(String host) {
        HttpService service = fake(HttpService.class, Map.of("host", host));
        HttpRequest request = fake(HttpRequest.class, Map.of("httpService", service));
        return fake(HttpRequestResponse.class, Map.of("request", request));
    }

    static ContextMenuEvent event(String... hosts) {
        Map<String, Object> answers = new HashMap<>();
        answers.put("selectedRequestResponses", List.of(hosts).stream().map(RadarMenuTest::rr).toList());
        return fake(ContextMenuEvent.class, answers);
    }

    final List<List<String>> revealed = new java.util.ArrayList<>();
    boolean off;

    JMenu menu(String... hosts) {
        List<Component> items = new RadarMenu(queue, tab, confirm, () -> off, revealed::add).provideMenuItems(event(hosts));
        assertEquals(1, items.size());
        return (JMenu) items.get(0);
    }

    /** Menu entries as text; "-" for a separator, submenus as "title > a, b". */
    static List<String> texts(JMenu menu) {
        List<String> out = new ArrayList<>();
        for (Component c : menu.getMenuComponents()) {
            if (c instanceof JPopupMenu.Separator) {
                out.add("-");
            } else if (c instanceof JMenu sub) {
                out.add(sub.getText() + " > " + String.join(", ", texts(sub)));
            } else {
                out.add(((JMenuItem) c).getText());
            }
        }
        return out;
    }

    static JMenuItem find(JMenu menu, String text) {
        for (Component c : menu.getMenuComponents()) {
            if (c instanceof JMenuItem item && item.getText().equals(text)) {
                return item;
            }
        }
        throw new AssertionError("no item " + text);
    }

    static void assertHtmlDisabled(JMenu menu) {
        assertEquals(Boolean.TRUE, menu.getClientProperty("html.disable"), menu.getText());
        for (Component c : menu.getMenuComponents()) {
            if (c instanceof JMenu sub) {
                assertHtmlDisabled(sub);
            } else if (c instanceof JComponent item && !(c instanceof JPopupMenu.Separator)) {
                assertEquals(Boolean.TRUE, item.getClientProperty("html.disable"), item.toString());
            }
        }
    }

    @Test
    void oneHostOffersParentsCheckAndTab() {
        JMenu m = menu("VPN.b.example.com");
        assertEquals("Hirdman Radar", m.getText());
        assertEquals(List.of("Find subdomains of > b.example.com, example.com",
                "Find subdomains and check for leaks > b.example.com, example.com", "-",
                "Check vpn.b.example.com for leaks", "-", "Show in Hirdman Radar tab"), texts(m));
        assertHtmlDisabled(m);
    }

    @Test
    void aPrivateProjectGetsOneInactiveItemInsteadOfTheChecks() {
        off = true;
        JMenu m = menu("vpn.example.com");
        assertEquals(List.of("Private project: nothing is sent", "-", "Show in Hirdman Radar tab"), texts(m));
        assertTrue(!find(m, "Private project: nothing is sent").isEnabled());
        assertHtmlDisabled(m);
        find(m, "Show in Hirdman Radar tab").doClick(0);
        assertEquals(List.of(List.of("vpn.example.com")), revealed);
        assertTrue(queue.jobs().isEmpty());
    }

    @Test
    void ipsGetOnlyTheTabItem() {
        assertEquals(List.of("Show in Hirdman Radar tab"), texts(menu("10.0.0.1")));
    }

    @Test
    void nothingSelectedShowsNoMenu() {
        assertTrue(new RadarMenu(queue, tab, confirm, () -> off, revealed::add).provideMenuItems(event()).isEmpty());
    }

    @Test
    void messageEditorHostCounts() {
        Map<String, Object> answers = new HashMap<>();
        answers.put("messageEditorRequestResponse", Optional.of(fake(
                burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class, Map.of("requestResponse", rr("a.example.com")))));
        List<Component> items = new RadarMenu(queue, tab, confirm, () -> off, revealed::add).provideMenuItems(fake(ContextMenuEvent.class, answers));
        assertTrue(texts((JMenu) items.get(0)).contains("Check a.example.com for leaks"));
    }

    @Test
    void clicksQueueTheRightJobs() {
        JMenu m = menu("vpn.b.example.com", "a.example.com");
        ((JMenu) m.getMenuComponent(0)).getItem(1).doClick(0);
        ((JMenu) m.getMenuComponent(1)).getItem(0).doClick(0);
        find(m, "Check 2 selected hosts for leaks").doClick(0);
        List<Job> jobs = queue.jobs();
        assertEquals(List.of(JobKind.FIND_SUBDOMAINS, JobKind.FIND_AND_CHECK, JobKind.CHECK_HOSTS),
                jobs.stream().map(Job::kind).toList());
        assertEquals("example.com", jobs.get(0).domain());
        assertEquals("b.example.com", jobs.get(1).domain());
        assertEquals(List.of("vpn.b.example.com", "a.example.com"), jobs.get(2).hosts());
    }

    @Test
    void showSelectsTheTabThroughItsTabbedPane() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Proxy", new JPanel());
        JPanel wrapper = new JPanel();
        wrapper.add(tab);
        tabs.addTab("Hirdman Radar", wrapper);
        find(menu("a.example.com"), "Show in Hirdman Radar tab").doClick(0);
        assertEquals(1, tabs.getSelectedIndex());
    }

    @Test
    void showWithoutTabbedPaneDoesNothing() {
        find(menu("a.example.com"), "Show in Hirdman Radar tab").doClick(0);
    }

    @Test
    void itemsWithoutARequestAreSkipped() {
        Map<String, Object> noRequest = new HashMap<>();
        noRequest.put("request", null);
        Map<String, Object> answers = new HashMap<>();
        answers.put("selectedRequestResponses", List.of(fake(HttpRequestResponse.class, noRequest), rr("a.example.com")));
        List<Component> items = new RadarMenu(queue, tab, confirm, () -> off, revealed::add).provideMenuItems(fake(ContextMenuEvent.class, answers));
        assertTrue(texts((JMenu) items.get(0)).contains("Check a.example.com for leaks"));
    }

    @Test
    void aHugeSelectionStopsAtAThousandHosts() {
        java.util.concurrent.atomic.AtomicInteger read = new java.util.concurrent.atomic.AtomicInteger();
        List<HttpRequestResponse> selected = new ArrayList<>();
        for (int i = 0; i < 1500; i++) {
            HttpRequestResponse plain = rr("h" + i + ".example.com");
            selected.add(fake(HttpRequestResponse.class, (m, a) -> {
                read.incrementAndGet();
                return m.equals("request") ? plain.request() : Fakes.DEFAULT;
            }));
        }
        Map<String, Object> answers = new HashMap<>();
        answers.put("selectedRequestResponses", selected);
        List<Component> items = new RadarMenu(queue, tab, confirm, () -> off, revealed::add).provideMenuItems(fake(ContextMenuEvent.class, answers));
        assertTrue(texts((JMenu) items.get(0)).contains("Check " + RadarMenu.MAX_HOSTS + " selected hosts for leaks"));
        assertEquals(RadarMenu.MAX_HOSTS, read.get());
    }

    @Test
    void repeatedHostsAreTakenOnce() {
        String[] same = new String[3000];
        Arrays.fill(same, "a.example.com");
        find(menu(same), "Show in Hirdman Radar tab").doClick(0);
        assertEquals(List.of(List.of("a.example.com")), revealed);
    }

    @Test
    void showPassesTheSelectedHostsToTheTab() {
        find(menu("A.example.com", "10.0.0.1", "b.example.com"), "Show in Hirdman Radar tab").doClick(0);
        assertEquals(List.of(List.of("A.example.com", "10.0.0.1", "b.example.com")), revealed);
    }

    @Test
    void aRequestWithoutAHostNameStillGetsTheMenu() {
        Map<String, Object> noHost = new HashMap<>();
        noHost.put("host", null);
        HttpService service = fake(HttpService.class, noHost);
        HttpRequest request = fake(HttpRequest.class, Map.of("httpService", service));
        Map<String, Object> answers = new HashMap<>();
        answers.put("selectedRequestResponses", List.of(fake(HttpRequestResponse.class, Map.of("request", request)),
                rr("vpn.example.com")));
        List<Component> items = new RadarMenu(queue, tab, confirm, () -> off, revealed::add).provideMenuItems(fake(ContextMenuEvent.class,
                answers));
        assertEquals(1, items.size());
    }
}
