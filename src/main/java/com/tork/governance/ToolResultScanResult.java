package com.tork.governance;

import java.util.Collections;
import java.util.List;

/**
 * Result of {@link ToolResultScanner#scanToolResult}. Mirrors
 * {@code ToolResultScanResult} in tork-js-sdk/src/tool-result-scan.ts.
 */
public final class ToolResultScanResult {

    /**
     * The payload with PII masked in place, structurally identical
     * otherwise. {@code null} when blocked is true. Sub-trees containing no
     * PII keep their original object identity, so a clean payload's
     * containers come back as the same {@link java.util.Map}/{@link java.util.List}
     * instances that were passed in.
     */
    private final Object sanitized;
    private final List<ToolResultFinding> findings;
    private final boolean blocked;
    /** Present only when blocked is true. */
    private final String reason;

    public ToolResultScanResult(Object sanitized, List<ToolResultFinding> findings, boolean blocked, String reason) {
        this.sanitized = sanitized;
        this.findings = Collections.unmodifiableList(findings);
        this.blocked = blocked;
        this.reason = reason;
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
}
