package com.tork.governance;

/**
 * Either {@code pii} (a detector match) or {@code injection} (a heuristic
 * pattern match). Mirrors {@code ToolResultFindingKind} in
 * tork-js-sdk/src/tool-result-scan.ts.
 */
public enum ToolResultFindingKind {
    PII("pii"),
    INJECTION("injection");

    private final String code;

    ToolResultFindingKind(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
