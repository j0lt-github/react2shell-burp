package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.model.ScanOptions;
import burp.model.ScanResult;
import burp.scanner.React2ShellScanner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * UI tab that orchestrates manual scans and renders status.
 */
public class React2ShellTab extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final React2ShellScanner scanner;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final JTextField targetField = new JTextField();
    private final JTextField pathField = new JTextField("/");
    private final JRadioButton safeCheckButton = new JRadioButton("Safe digest check");
    private final JRadioButton pocButton = new JRadioButton("PoC redirect check");
    private final JCheckBox windowsPayload = new JCheckBox("Windows payload");
    private final JCheckBox followRedirects = new JCheckBox("Follow same-host redirects", true);
    private final JTextField commandField = new JTextField("echo $((41*271))");
    private final JCheckBox collaboratorOob = new JCheckBox("Use Burp Collaborator (PoC)");
    private final JSpinner collaboratorWait = new JSpinner(new SpinnerNumberModel(6, 1, 30, 1));
    private final JTextArea headersArea = new JTextArea(4, 20);
    private final JTextArea logArea = new JTextArea();
    private final JLabel statusLabel = new JLabel("Ready");

    public React2ShellTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, React2ShellScanner scanner) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.scanner = scanner;

        setLayout(new BorderLayout(0, 8));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        safeCheckButton.addActionListener(e -> updateCommandEnabled());
        pocButton.addActionListener(e -> updateCommandEnabled());
        collaboratorOob.addActionListener(e -> updateCommandEnabled());
        updateCommandEnabled();

        add(buildHeader(), BorderLayout.NORTH);
        add(buildContent(), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);
    }

    public ScanOptions currentOptions() {
        ScanOptions options = new ScanOptions();
        options.setPath(pathField.getText().trim());
        options.setMode(safeCheckButton.isSelected() ? ScanOptions.Mode.SAFE_CHECK : ScanOptions.Mode.POC_REDIRECT);
        options.setWindowsPayload(windowsPayload.isSelected());
        options.setFollowRedirects(followRedirects.isSelected());
        options.setExtraHeaders(parseHeaders(headersArea.getText()));
        options.setCommand(commandField.getText());
        options.setUseCollaborator(collaboratorOob.isSelected());
        options.setCollaboratorWaitSeconds((Integer) collaboratorWait.getValue());
        return options;
    }

    public void populateFromRequest(IHttpRequestResponse message) {
        if (message == null) {
            return;
        }
        IRequestInfo info = helpers.analyzeRequest(message);
        URL url = info.getUrl();
        if (url != null) {
            String base = url.getProtocol() + "://" + url.getHost();
            if ((url.getProtocol().equalsIgnoreCase("http") && url.getPort() != 80) ||
                (url.getProtocol().equalsIgnoreCase("https") && url.getPort() != 443 && url.getPort() != -1)) {
                base += ":" + url.getPort();
            }
            targetField.setText(base);
            pathField.setText(url.getFile());
            appendLog("Loaded target from selection: " + base + url.getFile());
        }
    }

    public void runManualScan() {
        String rawTarget = targetField.getText().trim();
        if (rawTarget.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter a target URL or host first.", "Missing target", JOptionPane.WARNING_MESSAGE);
            return;
        }
        IHttpService service = buildService(rawTarget);
        if (service == null) {
            JOptionPane.showMessageDialog(this, "Could not parse target. Use forms like https://example.com", "Invalid target", JOptionPane.ERROR_MESSAGE);
            return;
        }

        ScanOptions options = currentOptions();
        appendLog("Launching scan against " + renderService(service) + options.getPath() + " (" + options.getMode() + ")");
        setBusy(true);

        executor.submit(() -> {
            ScanResult result = scanner.scan(service, options.getPath(), options);
            SwingUtilities.invokeLater(() -> renderResult(result));
        });
    }

    public void renderScanResult(ScanResult result) {
        SwingUtilities.invokeLater(() -> renderResult(result));
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    private void renderResult(ScanResult result) {
        setBusy(false);
        if (result == null) {
            statusLabel.setText("Scan failed");
            return;
        }
        String prefix;
        if (result.isErrored()) {
            prefix = "[error] ";
        } else if (result.isVulnerable()) {
            prefix = "[vulnerable] ";
        } else {
            prefix = "[clean] ";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(prefix).append(result.getMessage())
          .append(" | status ").append(result.getStatusCode())
          .append(" | ").append(result.getDurationMs()).append(" ms");
        if (result.getEvidence() != null) {
            sb.append(" | evidence: ").append(result.getEvidence());
        }
        appendLog(sb.toString());
        statusLabel.setText(sb.toString());
        if (result.getRequestResponse() != null) {
            callbacks.addScanIssue(new burp.React2ShellIssue(result.getRequestResponse(), helpers, result));
        }
    }

    private IHttpService buildService(String input) {
        try {
            String normalized = input.startsWith("http") ? input : "https://" + input;
            URL url = new URL(normalized);
            boolean https = url.getProtocol().equalsIgnoreCase("https");
            int port = url.getPort() == -1 ? (https ? 443 : 80) : url.getPort();
            return helpers.buildHttpService(url.getHost(), port, https);
        } catch (Exception e) {
            return null;
        }
    }

    private JPanel buildHeader() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        JLabel title = new JLabel("react2shellburp – CVE-2025-55182");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));

        JLabel subtitle = new JLabel("Detects React Server Components unsafe deserialization (Next.js / RSC).");
        subtitle.setFont(subtitle.getFont().deriveFont(Font.PLAIN, 12f));

        JPanel text = new JPanel();
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.add(title);
        text.add(Box.createVerticalStrut(2));
        text.add(subtitle);

        panel.add(text, BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildContent() {
        JPanel wrapper = new JPanel(new BorderLayout(0, 8));
        wrapper.add(buildFormPanel(), BorderLayout.NORTH);
        wrapper.add(buildLogPanel(), BorderLayout.CENTER);
        return wrapper;
    }

    private JPanel buildFormPanel() {
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Scan settings"),
                new EmptyBorder(6, 6, 6, 6)
        ));

        form.add(buildFormRow("Target", targetField, "e.g. https://example.com"));
        form.add(buildFormRow("Path", pathField, "e.g. /"));
        form.add(buildFormRow("Command", commandField, "Used in PoC redirect check (e.g. echo $((41*271)))"));
        form.add(buildModeRow());
        form.add(buildOptionsRow());
        form.add(buildCollaboratorRow());
        form.add(buildHeadersRow());
        form.add(buildRunRow());
        return form;
    }

    private JPanel buildFormRow(String label, JTextField field, String hint) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setBorder(new EmptyBorder(6, 0, 0, 0));
        JLabel lbl = new JLabel(label);
        lbl.setPreferredSize(new Dimension(70, 24));
        field.setToolTipText(hint);
        row.add(lbl, BorderLayout.WEST);
        row.add(field, BorderLayout.CENTER);
        return row;
    }

    private JPanel buildModeRow() {
        JPanel row = new JPanel(new GridLayout(1, 3, 10, 0));
        row.setBorder(new EmptyBorder(6, 0, 0, 0));
        ButtonGroup group = new ButtonGroup();
        group.add(safeCheckButton);
        group.add(pocButton);
        safeCheckButton.setSelected(true);

        row.add(safeCheckButton);
        row.add(pocButton);
        row.add(windowsPayload);
        return row;
    }

    private JPanel buildOptionsRow() {
        JPanel row = new JPanel(new GridLayout(1, 2, 10, 0));
        row.setBorder(new EmptyBorder(6, 0, 0, 0));
        row.add(followRedirects);
        row.add(new JLabel("")); // spacer
        return row;
    }

    private JPanel buildCollaboratorRow() {
        JPanel row = new JPanel(new BorderLayout());
        row.setBorder(new EmptyBorder(6, 0, 0, 0));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        left.add(collaboratorOob);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        right.add(new JLabel("Wait (s):"));
        collaboratorWait.setPreferredSize(new Dimension(60, 24));
        right.add(collaboratorWait);

        row.add(left, BorderLayout.WEST);
        row.add(right, BorderLayout.EAST);
        return row;
    }

    private JPanel buildHeadersRow() {
        JPanel row = new JPanel(new BorderLayout());
        row.setBorder(new EmptyBorder(6, 0, 0, 0));
        headersArea.setLineWrap(true);
        headersArea.setWrapStyleWord(true);
        row.add(new JLabel("Extra headers (one per line):"), BorderLayout.NORTH);
        row.add(new JScrollPane(headersArea), BorderLayout.CENTER);
        return row;
    }

    private JPanel buildRunRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton scanButton = new JButton("Run scan");
        scanButton.addActionListener(e -> runManualScan());
        row.add(scanButton);
        return row;
    }

    private JPanel buildLogPanel() {
        JPanel row = new JPanel(new BorderLayout());
        row.setBorder(new EmptyBorder(10, 0, 0, 0));
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        row.add(new JLabel("Activity"), BorderLayout.NORTH);
        row.add(new JScrollPane(logArea), BorderLayout.CENTER);
        JButton clear = new JButton("Clear log");
        clear.addActionListener(e -> logArea.setText(""));
        row.add(clear, BorderLayout.SOUTH);
        return row;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(new EmptyBorder(4, 0, 0, 0));
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 12f));
        footer.add(statusLabel, BorderLayout.WEST);
        return footer;
    }

    private void appendLog(String text) {
        logArea.append(text + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    private void setBusy(boolean busy) {
        statusLabel.setText(busy ? "Scanning..." : "Ready");
        setCursor(Cursor.getPredefinedCursor(busy ? Cursor.WAIT_CURSOR : Cursor.DEFAULT_CURSOR));
    }

    private Map<String, String> parseHeaders(String input) {
        Map<String, String> map = new LinkedHashMap<>();
        if (input == null || input.trim().isEmpty()) {
            return map;
        }
        String[] lines = input.split("\\r?\\n");
        for (String line : lines) {
            int idx = line.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String key = line.substring(0, idx).trim();
            String value = line.substring(idx + 1).trim();
            if (!key.isEmpty()) {
                map.put(key, value);
            }
        }
        return map;
    }

    private String renderService(IHttpService service) {
        String scheme = service.getProtocol();
        String host = service.getHost();
        int port = service.getPort();
        boolean standard = (scheme.equalsIgnoreCase("https") && port == 443)
                || (scheme.equalsIgnoreCase("http") && port == 80);
        return scheme + "://" + host + (standard ? "" : ":" + port);
    }

    private void updateCommandEnabled() {
        boolean pocSelected = pocButton.isSelected();
        commandField.setEnabled(pocSelected);
        commandField.setToolTipText("Executed on target when PoC redirect mode is selected.");
        collaboratorOob.setEnabled(pocSelected);
        collaboratorWait.setEnabled(pocSelected && collaboratorOob.isSelected());
    }
}
