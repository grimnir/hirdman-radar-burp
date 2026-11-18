package pro.hirdman.radar.issues;

import pro.hirdman.radar.model.Risk;

/**
 * Issue settings: create automatically, include hosts outside Burp's scope, lowest severity reported, and the radar site
 * (scheme://host[:port]) linked from issue details, or null for no link.
 */
public record IssueOptions(boolean auto, boolean includeOutOfScope, Risk lowest, String site) {
}
