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

/**
 * Burp Extender entry point.
 */
public class React2ShellExtension implements IBurpExtender, ITab, IScannerCheck, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private React2ShellScanner scanner;
    private React2ShellTab tab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("react2shellburp");

        scanner = new React2ShellScanner(callbacks, helpers);
        tab = new React2ShellTab(callbacks, helpers, scanner);

        callbacks.addSuiteTab(this);
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.printOutput("React2Shell scanner loaded. Default mode uses safe digest check. Switch to PoC redirect mode for stronger confirmation.");
    }

    @Override
    public String getTabCaption() {
        return "React2Shell";
    }

    @Override
    public Component getUiComponent() {
        return tab;
    }

    
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
        React2ShellIssue issue = new React2ShellIssue(stored, helpers, placeholder);
        List<IScanIssue> issues = new ArrayList<>();
        issues.add(issue);
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        ScanOptions options = tab.currentOptions();
        String path = helpers.analyzeRequest(baseRequestResponse).getUrl().getFile();
        ScanResult result = scanner.scan(baseRequestResponse.getHttpService(), path, options);
        if (result != null && result.isVulnerable() && result.getRequestResponse() != null) {
            return Collections.singletonList(new React2ShellIssue(result.getRequestResponse(), helpers, result));
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

    // --- IContextMenuFactory ---
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected == null || selected.length == 0) {
            return Collections.emptyList();
        }

        JMenuItem load = new JMenuItem("Load into React2Shell tab");
        load.addActionListener(e -> SwingUtilities.invokeLater(() -> tab.populateFromRequest(selected[0])));

        JMenuItem quickScan = new JMenuItem("Scan for React2Shell (CVE-2025-55182)");
        quickScan.addActionListener(e -> new Thread(() -> runContextScan(selected[0])).start());

        return Arrays.asList(load, quickScan);
    }

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
}
