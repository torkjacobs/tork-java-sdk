package com.tork.governance;

import java.util.List;

/**
 * What {@link Tork#scanToolResult} returns: the pure scan result plus the
 * receipt recording it. Mirrors {@code GovernedToolResultScanResult} in
 * tork-js-sdk/src/index.ts and Go's {@code ScanToolResultResult} in
 * tork-go-sdk/toolresultscan_client.go.
 */
public final class GovernedToolResultScanResult {

    private final Object sanitized;
    private final List<ToolResultFinding> findings;
    private final boolean blocked;
    private final String reason;
    private final Receipt receipt;

    public GovernedToolResultScanResult(Object sanitized, List<ToolResultFinding> findings, boolean blocked,
                                         String reason, Receipt receipt) {
        this.sanitized = sanitized;
        this.findings = findings;
        this.blocked = blocked;
        this.reason = reason;
        this.receipt = receipt;
    }

    public Object getSanitized() {
        return sanitized;
    }

    public List<ToolResultFinding> getFindings() {
        return findings;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public String getReason() {
        return reason;
    }

    /** Carries the {@code tool_result_scan} block. */
    public Receipt getReceipt() {
        return receipt;
    }
}
