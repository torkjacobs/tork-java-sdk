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
    private final List<String> region;
    private final String industry;

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
        this(action, output, matches, receipt, null, null);
    }

    /**
     * Create a new governance result with region and industry.
     *
     * @param action the action taken
     * @param output the governed output text
     * @param matches list of PII matches found
     * @param receipt the governance receipt
     * @param region optional regional PII profiles activated
     * @param industry optional industry profile activated
     */
    public GovernanceResult(GovernanceAction action, String output,
                            List<PIIDetector.PIIMatch> matches, Receipt receipt,
                            List<String> region, String industry) {
        this.action = action;
        this.output = output;
        this.matches = Collections.unmodifiableList(matches);
        this.receipt = receipt;
        this.hasPII = !matches.isEmpty();
        this.piiTypes = matches.stream()
            .map(PIIDetector.PIIMatch::getType)
            .collect(Collectors.toUnmodifiableSet());
        this.region = region;
        this.industry = industry;
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

    /**
     * Get the regional PII profiles that were activated.
     * @return list of region codes, or null if not specified
     */
    public List<String> getRegion() {
        return region;
    }

    /**
     * Get the industry profile that was activated.
     * @return industry name, or null if not specified
     */
    public String getIndustry() {
        return industry;
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
