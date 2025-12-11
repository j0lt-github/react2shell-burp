package burp.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Mutable options representing how a scan should be executed.
 */
public class ScanOptions {

    public enum Mode {
        SAFE_CHECK,
        POC_REDIRECT
    }

    private String path = "/";
    private Mode mode = Mode.SAFE_CHECK;
    private boolean windowsPayload = false;
    private boolean followRedirects = true;
    private Map<String, String> extraHeaders = new LinkedHashMap<>();
    private String command = "echo $((41*271))";
    private boolean useCollaborator = false;
    private int collaboratorWaitSeconds = 6;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        if (path == null || path.isEmpty()) {
            this.path = "/";
        } else if (path.startsWith("/")) {
            this.path = path;
        } else {
            this.path = "/" + path;
        }
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public boolean isWindowsPayload() {
        return windowsPayload;
    }

    public void setWindowsPayload(boolean windowsPayload) {
        this.windowsPayload = windowsPayload;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }

    public Map<String, String> getExtraHeaders() {
        return Collections.unmodifiableMap(extraHeaders);
    }

    public void setExtraHeaders(Map<String, String> extraHeaders) {
        this.extraHeaders = new LinkedHashMap<>(extraHeaders);
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        if (command == null || command.trim().isEmpty()) {
            this.command = "echo $((41*271))";
        } else {
            this.command = command.trim();
        }
    }

    public boolean isUseCollaborator() {
        return useCollaborator;
    }

    public void setUseCollaborator(boolean useCollaborator) {
        this.useCollaborator = useCollaborator;
    }

    public int getCollaboratorWaitSeconds() {
        return collaboratorWaitSeconds;
    }

    public void setCollaboratorWaitSeconds(int collaboratorWaitSeconds) {
        this.collaboratorWaitSeconds = Math.max(1, collaboratorWaitSeconds);
    }
}
