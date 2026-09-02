package com.tork.governance;

/**
 * Input to {@link ToolResultScanner#scanToolResult}. Mirrors
 * {@code ToolResultScanInput} in tork-js-sdk/src/tool-result-scan.ts.
 */
public final class ToolResultScanInput {

    /** Name of the tool that produced this result. Recorded on the receipt. */
    private final String toolName;
    /** URI of the MCP server (or other origin). Recorded on the receipt when present. Nullable. */
    private final String serverUri;
    /**
     * The tool result itself. Any JSON-shaped value reachable via
     * {@link java.util.Map}, {@link java.util.List}, arrays, strings,
     * numbers, booleans, and {@code null} -- it never leaves the machine.
     */
    private final Object payload;

    public ToolResultScanInput(String toolName, String serverUri, Object payload) {
        this.toolName = toolName;
        this.serverUri = serverUri;
        this.payload = payload;
    }

    public ToolResultScanInput(String toolName, Object payload) {
        this(toolName, null, payload);
    }

    public String getToolName() {
        return toolName;
    }

    public String getServerUri() {
        return serverUri;
    }

    public Object getPayload() {
        return payload;
    }
}
