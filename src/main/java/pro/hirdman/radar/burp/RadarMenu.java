package pro.hirdman.radar.burp;

import static pro.hirdman.radar.ui.PlainText.menu;
import static pro.hirdman.radar.ui.PlainText.menuItem;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
import java.awt.Container;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JTabbedPane;
import pro.hirdman.radar.jobs.JobKind;
import pro.hirdman.radar.jobs.JobQueue;
import pro.hirdman.radar.menu.MenuModel;
import pro.hirdman.radar.ui.SendConfirm;

/** Extensions > Hirdman Radar in Burp's context menus. Items only queue jobs: no network here, no focus change. */
public final class RadarMenu implements ContextMenuItemsProvider {

    /** Distinct hosts taken from a selection; the menu is built on the EDT, and Proxy history can select 50,000 rows. */
    static final int MAX_HOSTS = 1000;

    private final JobQueue queue;
    private final Component tab;
    private final SendConfirm confirm;
    private final Consumer<List<String>> reveal;

    public RadarMenu(JobQueue queue, Component tab, Consumer<List<String>> reveal) {
        this(queue, tab, SendConfirm.dialog(tab), reveal);
    }

    RadarMenu(JobQueue queue, Component tab, SendConfirm confirm, Consumer<List<String>> reveal) {
        this.queue = queue;
        this.tab = tab;
        this.confirm = confirm;
        this.reveal = reveal;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // Raw names are de-duplicated first, so each distinct one is normalized once.
        Set<String> raw = new LinkedHashSet<>();
        for (HttpRequestResponse rr : event.selectedRequestResponses()) {
            if (raw.size() >= MAX_HOSTS) {
                break;
            }
            addHost(raw, rr);
        }
        event.messageEditorRequestResponse().ifPresent(m -> addHost(raw, m.requestResponse()));
        if (raw.isEmpty()) {
            return List.of();
        }
        List<String> hosts = List.copyOf(raw);
        MenuModel model = MenuModel.of(hosts);
        JMenu root = menu("Hirdman Radar");
        if (!model.findDomains().isEmpty()) {
            root.add(domains("Find subdomains of", model.findDomains(),
                    d -> queue.submit(JobKind.FIND_SUBDOMAINS, d, List.of(), false)));
            root.add(domains("Find subdomains and check for leaks", model.findDomains(),
                    d -> queue.submit(JobKind.FIND_AND_CHECK, d, List.of(), false)));
            root.addSeparator();
        }
        if (model.checkLabel() != null) {
            root.add(item(model.checkLabel(), () -> {
                if (confirm.allows(queue.toSend(model.checkHosts()).size())) {
                    queue.submit(JobKind.CHECK_HOSTS, null, model.checkHosts(), false);
                }
            }));
            root.addSeparator();
        }
        root.add(item("Show in Hirdman Radar tab", () -> show(tab, reveal, hosts)));
        return List.of(root);
    }

    private static void addHost(Collection<String> hosts, HttpRequestResponse rr) {
        Optional.ofNullable(rr).map(HttpRequestResponse::request).map(HttpRequest::httpService).map(HttpService::host)
                .ifPresent(hosts::add);
    }

    private static JMenu domains(String title, List<String> domains, Consumer<String> onClick) {
        JMenu submenu = menu(title);
        domains.forEach(d -> submenu.add(item(d, () -> onClick.accept(d))));
        return submenu;
    }

    private static JMenuItem item(String text, Runnable onClick) {
        JMenuItem item = menuItem(text);
        item.addActionListener(e -> onClick.run());
        return item;
    }

    /** "Show in Hirdman Radar tab": marks the hosts in the tab and brings the tab to the front. */
    public static void show(Component tab, Consumer<List<String>> reveal, List<String> hosts) {
        reveal.accept(hosts);
        showTab(tab);
    }

    /** Selects the tab through its nearest JTabbedPane ancestor; does nothing when there is none. */
    private static void showTab(Component tab) {
        Component child = tab;
        for (Container p = tab.getParent(); p != null; child = p, p = p.getParent()) {
            if (p instanceof JTabbedPane tabs) {
                int i = tabs.indexOfComponent(child);
                if (i >= 0) {
                    tabs.setSelectedIndex(i);
                }
                return;
            }
        }
    }
}
