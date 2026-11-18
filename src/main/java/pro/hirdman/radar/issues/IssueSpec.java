package pro.hirdman.radar.issues;

/** One Burp issue to create. Severity and confidence are Burp's names in lower case; HTML fields are already cleaned. */
public record IssueSpec(String name, String detail, String remediation, String baseUrl, String severity, String confidence,
        String background) {

    /** Burp cannot update an issue, so the same name on the same host is created once. */
    public String key() {
        return key(name, baseUrl);
    }

    public static String key(String name, String baseUrl) {
        return name + "|" + baseUrl;
    }
}
