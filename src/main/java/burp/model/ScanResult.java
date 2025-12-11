package burp.model;

import burp.IHttpRequestResponse;

/**
 * Holds outcome of a single scan attempt.
 */
public class ScanResult {
    private final boolean vulnerable;
    private final boolean errored;
    private final String message;
    private final IHttpRequestResponse requestResponse;
    private final long durationMs;
    private final int statusCode;
    private final String evidence;
    private final String pathTested;
    private final String commandUsed;
    private final boolean collaboratorHit;
    private final String collaboratorEvidence;

    public ScanResult(
            boolean vulnerable,
            boolean errored,
            String message,
            IHttpRequestResponse requestResponse,
            long durationMs,
            int statusCode,
            String evidence,
            String pathTested,
            String commandUsed,
            boolean collaboratorHit,
            String collaboratorEvidence) {
        this.vulnerable = vulnerable;
        this.errored = errored;
        this.message = message;
        this.requestResponse = requestResponse;
        this.durationMs = durationMs;
        this.statusCode = statusCode;
        this.evidence = evidence;
        this.pathTested = pathTested;
        this.commandUsed = commandUsed;
        this.collaboratorHit = collaboratorHit;
        this.collaboratorEvidence = collaboratorEvidence;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public boolean isErrored() {
        return errored;
    }

    public String getMessage() {
        return message;
    }

    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getPathTested() {
        return pathTested;
    }

    public String getCommandUsed() {
        return commandUsed;
    }

    public boolean isCollaboratorHit() {
        return collaboratorHit;
    }

    public String getCollaboratorEvidence() {
        return collaboratorEvidence;
    }
}
