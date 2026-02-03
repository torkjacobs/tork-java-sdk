package com.tork.governance;

/**
 * Enumeration of governance actions that can be taken on input.
 */
public enum GovernanceAction {
    /** Input is allowed to pass through unchanged */
    ALLOW("allow"),

    /** Input contains PII that has been redacted */
    REDACT("redact"),

    /** Input is blocked and should not be processed */
    DENY("deny"),

    /** Input requires human review before processing */
    ESCALATE("escalate");

    private final String code;

    GovernanceAction(String code) {
        this.code = code;
    }

    /**
     * Get the code identifier for this action.
     * @return the code string
     */
    public String getCode() {
        return code;
    }

    /**
     * Find a GovernanceAction by its code.
     * @param code the code to search for
     * @return the matching GovernanceAction or null if not found
     */
    public static GovernanceAction fromCode(String code) {
        for (GovernanceAction action : values()) {
            if (action.code.equals(code)) {
                return action;
            }
        }
        return null;
    }
}
