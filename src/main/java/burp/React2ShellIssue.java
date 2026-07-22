package burp;

import burp.model.ScanResult;

import java.net.URL;

/**
 * Scanner issue representation for React2Shell findings.
 */
public class React2ShellIssue implements IScanIssue {
    private final IHttpRequestResponse[] messages;
    private final IExtensionHelpers helpers;
    private final ScanResult result;
    private final URL url;

    public React2ShellIssue(IHttpRequestResponse message, IExtensionHelpers helpers, ScanResult result) {
        this.messages = new IHttpRequestResponse[]{message};
        this.helpers = helpers;
        this.result = result;
        this.url = helpers.analyzeRequest(message).getUrl();
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return messages;
    }

    @Override
    public IHttpService getHttpService() {
        return messages[0].getHttpService();
    }

    @Override
    public String getConfidence() {
        return result.isVulnerable() ? "Certain" : "Firm";
    }

    @Override
    public String getIssueBackground() {
        return "CVE-2025-55182 (React2Shell) is a pre-authentication remote code execution flaw in React Server Components (react-server-dom-*). " +
                "Server Action endpoints deserialize attacker-controlled payloads, allowing arbitrary code execution. " +
                "Affected: react-server-dom-webpack/turbopack/parcel versions 19.0.0, 19.1.0, 19.1.1, 19.2.0 and frameworks that bundle them.";
    }

    /**
     * Issue 7b: Burp renders issue detail strings as HTML. Any server-controlled
     * value included verbatim could inject arbitrary HTML — including remote
     * image tags that act as beacons when an analyst views the finding.
     * All response-derived fields are HTML-encoded before inclusion.
     */
    @Override
    public String getIssueDetail() {
        StringBuilder sb = new StringBuilder();
        sb.append("Path tested: ").append(htmlEncode(result.getPathTested()));
        sb.append("<br>Status code: ").append(result.getStatusCode());
        sb.append("<br>Evidence: ")
          .append(result.getEvidence() == null ? "None captured" : htmlEncode(result.getEvidence()));
        if (result.getCommandUsed() != null) {
            sb.append("<br>Command (PoC): ").append(htmlEncode(result.getCommandUsed()));
        }
        if (result.isCollaboratorHit()) {
            sb.append("<br>Collaborator: ").append(htmlEncode(result.getCollaboratorEvidence()));
        }
        sb.append("<br>Mode: ").append(htmlEncode(result.getMessage()));
        return sb.toString();
    }

    @Override
    public String getIssueName() {
        return "React2Shell / CVE-2025-55182";
    }

    @Override
    public int getIssueType() {
        return 0x08000000; // extension defined
    }

    @Override
    public String getRemediationBackground() {
        return "Upgrade to patched React Server Components releases (19.0.1 / 19.1.2 / 19.2.1) or framework versions carrying the fix. " +
                "If upgrading immediately is not possible, temporarily disable Server Actions or block POST requests with Next-Action/RSC headers.";
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public String getSeverity() {
        return result.isVulnerable() ? "High" : "Information";
    }

    @Override
    public URL getUrl() {
        return url;
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    /**
     * HTML-encodes a string so that server-controlled values cannot inject
     * markup into Burp's issue detail panel.
     *
     * @param input the raw string (may be null)
     * @return the HTML-safe string, or an empty string if input is null
     */
    private static String htmlEncode(String input) {
        if (input == null) {
            return "";
        }
        return input
                .replace("&",  "&amp;")
                .replace("<",  "&lt;")
                .replace(">",  "&gt;")
                .replace("\"", "&quot;")
                .replace("'",  "&#39;");
    }
}
