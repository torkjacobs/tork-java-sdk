package com.tork.governance;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Optional parameters to {@link ToolResultScanner#scanToolResult}. Mirrors
 * {@code ToolResultScanOptions} in tork-js-sdk/src/tool-result-scan.ts.
 */
public final class ToolResultScanOptions {

    /**
     * Block the result when the injection heuristics fire. Default false:
     * detect and report, let the caller decide. When true and an injection
     * pattern matches, the result's blocked is true, reason is set, and
     * sanitized is {@code null} -- there is deliberately no masked payload
     * to accidentally append.
     */
    private boolean blockOnInjection = false;

    /**
     * Extra redaction patterns, applied after the default PII detector's
     * redaction. NOTE (inherited from the JS/Go SDKs): custom patterns
     * redact but are not counted, so they can change {@code sanitized}
     * without producing a finding.
     */
    private Map<String, Pattern> customPatterns;

    /**
     * Maximum nesting depth to walk. Deeper values are passed through
     * unscanned and unmodified. {@code null} means "use the default" (32).
     * Unlike the Go port, Java can express a literal 0 (scan the root value
     * only, never descend into a container) because this field is a boxed
     * {@link Integer}, not a primitive with an ambiguous zero-value.
     */
    private Integer maxDepth;

    public boolean isBlockOnInjection() {
        return blockOnInjection;
    }

    public ToolResultScanOptions setBlockOnInjection(boolean blockOnInjection) {
        this.blockOnInjection = blockOnInjection;
        return this;
    }

    public Map<String, Pattern> getCustomPatterns() {
        return customPatterns;
    }

    public ToolResultScanOptions setCustomPatterns(Map<String, Pattern> customPatterns) {
        this.customPatterns = customPatterns;
        return this;
    }

    public Integer getMaxDepth() {
        return maxDepth;
    }

    public ToolResultScanOptions setMaxDepth(Integer maxDepth) {
        this.maxDepth = maxDepth;
        return this;
    }
}
