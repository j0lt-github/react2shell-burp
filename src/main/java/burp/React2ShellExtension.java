package burp;

import burp.model.ScanOptions;
import burp.model.ScanResult;
import burp.scanner.React2ShellScanner;
import burp.ui.React2ShellTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Burp Extender entry point for the React Server Components RCE Scanner.
 *
 * <p>Implements {@link IExtensionStateListener} so that the executor service
 * owned by {@link React2ShellTab} and any raw threads spawned from the context
 * menu are properly shut down when the extension is unloaded, preventing class
 * loader leaks that would otherwise force a Burp restart on each reload.</p>
 */
public class React2ShellExtension implements IBurpExtender, ITab, IScannerCheck,
        IContextMenuFactory, IExtensionStateListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private React2ShellScanner scanner;
    private React2ShellTab tab;

    /**
     * Tracks raw threads spawned by {@link #createMenuItems} so they can be
     * interrupted in {@link #extensionUnloaded()}.
     */
    private final CopyOnWriteArrayList<Thread> contextMenuThreads = new CopyOnWriteArrayList<>();

    // -----------------------------------------------------------------------
    // IBurpExtender
    // -----------------------------------------------------------------------

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Issue 1: use a name that clearly describes the unique capability.
        callbacks.setExtensionName("React2Shell RCE Scanner and Validator");

        scanner = new React2ShellScanner(callbacks, helpers);
        tab = new React2ShellTab(callbacks, helpers, scanner);

        callbacks.addSuiteTab(this);
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);

        // Issue 2: register this instance as an extension-state listener so
        // extensionUnloaded() is called when the extension is removed/reloaded.
        callbacks.registerExtensionStateListener(this);

        callbacks.printOutput(
                "React2Shell RCE Scanner and Validator loaded. " +
                "Default mode uses safe digest check. " +
                "Switch to PoC redirect mode for stronger confirmation."
        );
    }

    // -----------------------------------------------------------------------
    // IExtensionStateListener  (Issue 2)
    // -----------------------------------------------------------------------

    /**
     * Called by Burp when the extension is unloaded or Burp is closing.
     * Shuts down the executor owned by the UI tab and interrupts any in-flight
     * context-menu scan threads to allow the class loader to be GC'd cleanly.
     */
    @Override
    public void extensionUnloaded() {
        // Shut down the tab's ExecutorService (and the scanner's
        // ScheduledExecutorService via the chain).
        if (tab != null) {
            tab.shutdown();
        }
        // Interrupt any raw threads that were started from createMenuItems.
        for (Thread t : contextMenuThreads) {
            if (t.isAlive()) {
                t.interrupt();
            }
        }
        contextMenuThreads.clear();
    }

    // -----------------------------------------------------------------------
    // ITab
    // -----------------------------------------------------------------------

    @Override
    public String getTabCaption() {
        return "React2Shell";
    }

    @Override
    public Component getUiComponent() {
        return tab;
    }

    // -----------------------------------------------------------------------
    // IScannerCheck
    // -----------------------------------------------------------------------

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse == null || baseRequestResponse.getResponse() == null) {
            return null;
        }
        if (!scanner.looksLikeRscEndpoint(baseRequestResponse)) {
            return null;
        }

        IHttpRequestResponse stored = callbacks.saveBuffersToTempFiles(baseRequestResponse);
        ScanResult placeholder = new ScanResult(
                false,
                false,
                "React Server Components patterns detected. Run active scan for CVE-2025-55182.",
                stored,
                0L,
                helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode(),
                "RSC markers present (text/x-component, resolved_model, or RSC headers).",
                helpers.analyzeRequest(baseRequestResponse).getUrl().getFile(),
                null,
                false,
                null
        );
        List<IScanIssue> issues = new ArrayList<>();
        issues.add(new React2ShellIssue(stored, helpers, placeholder));
        return issues;
    }

    /**
     * Issue 4: Only probe requests that look like React Server Component
     * endpoints. Without this guard, Burp's scanner would send CVE-2025-55182
     * probes for every insertion point on every request, including endpoints
     * that are clearly unrelated (GET requests, static assets, non-Next.js
     * paths), generating unnecessary traffic and noise.
     */
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
                                         IScannerInsertionPoint insertionPoint) {
        // Lightweight pre-filter: only proceed for POST requests whose path or
        // headers suggest a React Server Component / Next.js Server Action.
        if (!isLikelyRscRequest(baseRequestResponse)) {
            return Collections.emptyList();
        }

        ScanOptions options = tab.currentOptions();
        String path = helpers.analyzeRequest(baseRequestResponse).getUrl().getFile();
        ScanResult result = scanner.scan(baseRequestResponse.getHttpService(), path, options);
        if (result != null && result.isVulnerable() && result.getRequestResponse() != null) {
            return Collections.singletonList(
                    new React2ShellIssue(result.getRequestResponse(), helpers, result));
        }
        return Collections.emptyList();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())
                && existingIssue.getUrl().equals(newIssue.getUrl())) {
            return -1; // drop new
        }
        return 0;
    }

    // -----------------------------------------------------------------------
    // IContextMenuFactory
    // -----------------------------------------------------------------------

    /**
     * Issue 5: Only surface context menu items in the Burp contexts where
     * HTTP messages represent full requests that are meaningful to scan —
     * Proxy history, Target site map, and Scanner. Returning an empty list
     * in all other contexts (e.g., Intruder payload editor, Decoder) prevents
     * the items from appearing where they cannot usefully be applied.
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        int ctx = invocation.getInvocationContext();
        if (ctx != IContextMenuInvocation.CONTEXT_PROXY_HISTORY
                && ctx != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE
                && ctx != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE
                && ctx != IContextMenuInvocation.CONTEXT_SCANNER_RESULTS
                && ctx != IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                && ctx != IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            return Collections.emptyList();
        }

        IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected == null || selected.length == 0) {
            return Collections.emptyList();
        }

        JMenuItem load = new JMenuItem("Load into React2Shell tab");
        load.addActionListener(e ->
                SwingUtilities.invokeLater(() -> tab.populateFromRequest(selected[0])));

        JMenuItem quickScan = new JMenuItem("Scan for React Server Components RCE (CVE-2025-55182)");
        quickScan.addActionListener(e -> {
            // Issue 2: track the thread so extensionUnloaded() can interrupt it.
            Thread t = new Thread(() -> runContextScan(selected[0]));
            t.setDaemon(true);
            contextMenuThreads.add(t);
            t.start();
            // Prune completed threads to avoid unbounded list growth.
            contextMenuThreads.removeIf(thread -> !thread.isAlive());
        });

        return Arrays.asList(load, quickScan);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void runContextScan(IHttpRequestResponse message) {
        try {
            ScanOptions options = tab.currentOptions();
            String path = helpers.analyzeRequest(message).getUrl().getFile();
            ScanResult result = scanner.scan(message.getHttpService(), path, options);
            tab.renderScanResult(result);
            if (result != null && result.getRequestResponse() != null) {
                callbacks.addScanIssue(new React2ShellIssue(result.getRequestResponse(), helpers, result));
            }
        } catch (Exception e) {
            callbacks.printError("React2Shell context scan failed: " + e.getMessage());
        }
    }

    /**
     * Returns {@code true} when the request looks like a React Server
     * Components / Next.js Server Action endpoint. Checks are intentionally
     * cheap (string comparisons on already-parsed headers) so they add
     * negligible overhead to the scanner thread pool.
     *
     * <p>A request qualifies when <em>any</em> of the following hold:</p>
     * <ul>
     *   <li>The HTTP method is POST <em>and</em> the path contains a known
     *       RSC segment ({@code _next/}, {@code __nextjs_}, {@code action},
     *       or {@code server}).</li>
     *   <li>The {@code Next-Action} or {@code RSC-Action-Id} request header
     *       is present.</li>
     *   <li>The {@code Content-Type} request header contains
     *       {@code text/x-component} or {@code multipart/form-data} (the two
     *       content types used by Server Action payloads).</li>
     * </ul>
     */
    private boolean isLikelyRscRequest(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getRequest() == null) {
            return false;
        }
        IRequestInfo info = helpers.analyzeRequest(requestResponse);
        String method = info.getMethod();
        if (!"POST".equalsIgnoreCase(method)) {
            return false;
        }

        String path = info.getUrl().getFile().toLowerCase(Locale.ROOT);
        if (path.contains("_next/") || path.contains("__nextjs_")
                || path.contains("server-action") || path.contains("rsc")) {
            return true;
        }

        List<String> headers = info.getHeaders();
        for (String header : headers) {
            String lower = header.toLowerCase(Locale.ROOT);
            if (lower.startsWith("next-action:") || lower.startsWith("rsc-action-id:")) {
                return true;
            }
            if (lower.startsWith("content-type:")
                    && (lower.contains("text/x-component") || lower.contains("multipart/form-data"))) {
                return true;
            }
        }
        return false;
    }
}
