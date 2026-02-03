package com.tork.governance;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Result of a governance operation.
 * Contains the action taken, the governed output, PII detection results, and a receipt.
 */
public class GovernanceResult {
    private final GovernanceAction action;
    private final String output;
    private final List<PIIDetector.PIIMatch> matches;
    private final Receipt receipt;
    private final boolean hasPII;
    private final Set<PIIType> piiTypes;

    /**
     * Create a new governance result.
     *
     * @param action the action taken
     * @param output the governed output text
     * @param matches list of PII matches found
     * @param receipt the governance receipt
     */
    public GovernanceResult(GovernanceAction action, String output,
                            List<PIIDetector.PIIMatch> matches, Receipt receipt) {
        this.action = action;
        this.output = output;
        this.matches = Collections.unmodifiableList(matches);
        this.receipt = receipt;
        this.hasPII = !matches.isEmpty();
        this.piiTypes = matches.stream()
            .map(PIIDetector.PIIMatch::getType)
            .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Get the governance action taken.
     * @return the action
     */
    public GovernanceAction getAction() {
        return action;
    }

    /**
     * Get the governed output text.
     * @return the output
     */
    public String getOutput() {
        return output;
    }

    /**
     * Get the list of PII matches found.
     * @return unmodifiable list of matches
     */
    public List<PIIDetector.PIIMatch> getMatches() {
        return matches;
    }

    /**
     * Get the governance receipt.
     * @return the receipt
     */
    public Receipt getReceipt() {
        return receipt;
    }

    /**
     * Check if PII was detected.
     * @return true if PII was found
     */
    public boolean hasPII() {
        return hasPII;
    }

    /**
     * Get the types of PII detected.
     * @return unmodifiable set of PII types
     */
    public Set<PIIType> getPiiTypes() {
        return piiTypes;
    }

    /**
     * Get the count of PII matches.
     * @return number of matches
     */
    public int getPiiCount() {
        return matches.size();
    }

    /**
     * Check if the action allows processing to continue.
     * @return true if action is ALLOW or REDACT
     */
    public boolean isAllowed() {
        return action == GovernanceAction.ALLOW || action == GovernanceAction.REDACT;
    }

    /**
     * Check if the request was blocked.
     * @return true if action is DENY
     */
    public boolean isDenied() {
        return action == GovernanceAction.DENY;
    }

    @Override
    public String toString() {
        return "GovernanceResult{" +
                "action=" + action +
                ", hasPII=" + hasPII +
                ", piiTypes=" + piiTypes +
                ", receiptId=" + receipt.getReceiptId() +
                '}';
    }
}
