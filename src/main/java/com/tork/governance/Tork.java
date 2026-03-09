package com.tork.governance;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Main Tork governance client.
 *
 * <p>Provides on-device AI governance with PII detection, redaction,
 * and cryptographic receipts.</p>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * Tork tork = new Tork();
 *
 * GovernanceResult result = tork.govern("My email is test@example.com");
 *
 * System.out.println(result.getOutput()); // "My email is [EMAIL_REDACTED]"
 * System.out.println(result.hasPII());    // true
 * System.out.println(result.getReceipt().getReceiptId()); // "rcpt_..."
 * }</pre>
 */
public class Tork {
    private final String apiKey;
    private final PIIDetector detector;
    private final TorkConfig config;

    // Statistics
    private final AtomicLong totalCalls = new AtomicLong(0);
    private final AtomicLong totalPIIDetected = new AtomicLong(0);
    private final AtomicLong totalProcessingTimeNanos = new AtomicLong(0);

    /**
     * Create a new Tork client with default configuration.
     */
    public Tork() {
        this(null, new TorkConfig());
    }

    /**
     * Create a new Tork client with an API key.
     *
     * @param apiKey optional API key for future cloud features
     */
    public Tork(String apiKey) {
        this(apiKey, new TorkConfig());
    }

    /**
     * Create a new Tork client with configuration.
     *
     * @param apiKey optional API key
     * @param config configuration options
     */
    public Tork(String apiKey, TorkConfig config) {
        this.apiKey = apiKey;
        this.detector = new PIIDetector();
        this.config = config != null ? config : new TorkConfig();
    }

    /**
     * Apply governance to input text with regional and industry-specific detection.
     *
     * @param input the text to govern
     * @param region optional list of regional PII profiles (e.g. ["ae", "in"])
     * @param industry optional industry profile (e.g. "healthcare", "finance", "legal")
     * @return governance result with action, output, and receipt
     */
    public GovernanceResult govern(String input, List<String> region, String industry) {
        return govern(input, region, industry, null);
    }

    /**
     * Apply governance to input text with regional, industry, and agent/session context.
     *
     * @param input the text to govern
     * @param region optional list of regional PII profiles (e.g. ["ae", "in"])
     * @param industry optional industry profile (e.g. "healthcare", "finance", "legal")
     * @param sessionContext optional agent/session context for multi-agent tracking
     * @return governance result with action, output, and receipt
     */
    public GovernanceResult govern(String input, List<String> region, String industry,
                                    SessionContext sessionContext) {
        GovernanceResult result = govern(input);
        return new GovernanceResult(
            result.getAction(), result.getOutput(), result.getMatches(),
            result.getReceipt(), region, industry, sessionContext
        );
    }

    /**
     * Apply governance to input text.
     *
     * <p>Detects PII and redacts it, generating a cryptographic receipt
     * for audit purposes.</p>
     *
     * @param input the text to govern
     * @return governance result with action, output, and receipt
     */
    public GovernanceResult govern(String input) {
        if (input == null || input.isEmpty()) {
            return new GovernanceResult(
                GovernanceAction.ALLOW,
                input != null ? input : "",
                List.of(),
                Receipt.generate(input != null ? input : "", input != null ? input : "",
                                GovernanceAction.ALLOW)
            );
        }

        long startTime = System.nanoTime();

        // Detect PII
        List<PIIDetector.PIIMatch> matches = detector.detect(input);

        GovernanceAction action;
        String output;

        if (matches.isEmpty()) {
            action = GovernanceAction.ALLOW;
            output = input;
        } else {
            action = config.getDefaultAction();
            if (action == GovernanceAction.REDACT) {
                output = detector.redact(input, matches);
            } else {
                output = input;
            }
            totalPIIDetected.incrementAndGet();
        }

        long processingTime = System.nanoTime() - startTime;
        totalCalls.incrementAndGet();
        totalProcessingTimeNanos.addAndGet(processingTime);

        Receipt receipt = Receipt.generate(input, output, action, processingTime);

        return new GovernanceResult(action, output, matches, receipt);
    }

    /**
     * Check if text contains PII without redacting.
     *
     * @param text the text to check
     * @return true if PII is detected
     */
    public boolean containsPII(String text) {
        return detector.containsPII(text);
    }

    /**
     * Check if text contains a specific type of PII.
     *
     * @param text the text to check
     * @param type the PII type to look for
     * @return true if the specified PII type is detected
     */
    public boolean containsPII(String text, PIIType type) {
        return detector.containsPII(text, type);
    }

    /**
     * Get the configured API key.
     * @return the API key or null
     */
    public String getApiKey() {
        return apiKey;
    }

    /**
     * Get the current configuration.
     * @return the configuration
     */
    public TorkConfig getConfig() {
        return config;
    }

    /**
     * Get the total number of governance calls made.
     * @return call count
     */
    public long getTotalCalls() {
        return totalCalls.get();
    }

    /**
     * Get the total number of calls that detected PII.
     * @return PII detection count
     */
    public long getTotalPIIDetected() {
        return totalPIIDetected.get();
    }

    /**
     * Get the average processing time in nanoseconds.
     * @return average processing time
     */
    public long getAverageProcessingTimeNanos() {
        long calls = totalCalls.get();
        if (calls == 0) return 0;
        return totalProcessingTimeNanos.get() / calls;
    }

    /**
     * Reset statistics counters.
     */
    public void resetStats() {
        totalCalls.set(0);
        totalPIIDetected.set(0);
        totalProcessingTimeNanos.set(0);
    }

    /**
     * Configuration options for Tork.
     */
    public static class TorkConfig {
        private GovernanceAction defaultAction = GovernanceAction.REDACT;
        private String policyVersion = "1.0.0";

        public GovernanceAction getDefaultAction() {
            return defaultAction;
        }

        public TorkConfig setDefaultAction(GovernanceAction action) {
            this.defaultAction = action;
            return this;
        }

        public String getPolicyVersion() {
            return policyVersion;
        }

        public TorkConfig setPolicyVersion(String version) {
            this.policyVersion = version;
            return this;
        }
    }
}
