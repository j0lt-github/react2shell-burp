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

    @Override
    public String getIssueDetail() {
        StringBuilder sb = new StringBuilder();
        sb.append("Path tested: ").append(result.getPathTested());
        sb.append("<br>Status code: ").append(result.getStatusCode());
        sb.append("<br>Evidence: ").append(result.getEvidence() == null ? "None captured" : result.getEvidence());
        if (result.getCommandUsed() != null) {
            sb.append("<br>Command (PoC): ").append(result.getCommandUsed());
        }
        if (result.isCollaboratorHit()) {
            sb.append("<br>Collaborator: ").append(result.getCollaboratorEvidence());
        }
        sb.append("<br>Mode: ").append(result.getMessage());
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
}
