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
            output = detector.redact(input, matches);
            totalPIIDetected.incrementAndGet();
        }

        long processingTime = System.nanoTime() - startTime;
        totalCalls.incrementAndGet();
        totalProcessingTimeNanos.addAndGet(processingTime);

        Receipt receipt = Receipt.generate(input, output, action, processingTime);

        return new GovernanceResult(action, output, matches, receipt);
    }

    /**
     * Scan a tool result (MCP server response, or any external system's
     * output) for PII and prompt injection BEFORE it is appended to model
     * context, and record the scan on a receipt.
     *
     * <p>The scan itself is the pure {@link ToolResultScanner#scanToolResult}
     * -- on-device, synchronous, zero network calls, using the same PII
     * detector as {@link #govern(String)}. This method adds the receipt:
     * {@code receipt.getToolResultScan()} carries counts by kind and type,
     * the tool name, the server URI, whether the result was blocked, and the
     * SDK version. It never carries the payload, a matched substring, or a
     * location path.</p>
     *
     * <p>This is a CLIENT-SIDE, CLIENT-ATTESTED control: it runs in the
     * caller's process, so the receipt records {@code attested_by: "client"}
     * and {@code capture_mode: "edge"} -- Tork did not execute this scan and
     * cannot verify it ran at all. Enforcement at the gateway, where a caller
     * cannot skip the scan, is a separate and later control.</p>
     *
     * <p>Action mapping (fixed, NOT {@code config.defaultAction}: unlike
     * {@link #govern(String)}, this path always returns masked output when it
     * returns any, so the action must describe what actually happened to the
     * tool result):</p>
     * <ul>
     *   <li>blocked &rarr; DENY (nothing is returned to append)</li>
     *   <li>injection detected &rarr; ESCALATE (returned, flagged for a human)</li>
     *   <li>PII masked &rarr; REDACT</li>
     *   <li>nothing found &rarr; ALLOW</li>
     * </ul>
     *
     * @param input the tool result to scan
     * @return the scan result plus a receipt carrying the tool_result_scan block
     */
    public GovernedToolResultScanResult scanToolResult(ToolResultScanInput input) {
        return scanToolResult(input, new ToolResultScanOptions());
    }

    /**
     * As {@link #scanToolResult(ToolResultScanInput)}, with options
     * (block-on-injection, custom redaction patterns, max traversal depth).
     *
     * @param input   the tool result to scan
     * @param options optional scan behavior
     * @return the scan result plus a receipt carrying the tool_result_scan block
     */
    public GovernedToolResultScanResult scanToolResult(ToolResultScanInput input, ToolResultScanOptions options) {
        long startTime = System.nanoTime();

        ToolResultScanOptions effectiveOptions = options != null ? options : new ToolResultScanOptions();
        ToolResultScanResult scan = ToolResultScanner.scanToolResult(input, effectiveOptions);

        int piiCount = ToolResultScanner.scanPIICount(scan.getFindings());
        int injectionCount = ToolResultScanner.scanInjectionCount(scan.getFindings());

        GovernanceAction action;
        if (scan.isBlocked()) {
            action = GovernanceAction.DENY;
        } else if (injectionCount > 0) {
            action = GovernanceAction.ESCALATE;
        } else if (piiCount > 0) {
            action = GovernanceAction.REDACT;
        } else {
            action = GovernanceAction.ALLOW;
        }

        long processingTime = System.nanoTime() - startTime;
        totalCalls.incrementAndGet();
        if (piiCount > 0) {
            totalPIIDetected.incrementAndGet();
        }
        totalProcessingTimeNanos.addAndGet(processingTime);

        ToolResultScanReceiptBlock block = ToolResultScanner.buildToolResultScanBlock(
            input.getToolName(), input.getServerUri(), scan, Version.SDK_VERSION);

        // Hashes, not content: hashText is SHA256, so neither the payload nor
        // the sanitized copy is recoverable from the receipt. A blocked scan
        // has no output to hash and records the hash of the empty string.
        String stableInput = ToolResultScanner.stableStringify(input.getPayload());
        String stableOutput = scan.isBlocked() ? "" : ToolResultScanner.stableStringify(scan.getSanitized());
        Receipt receipt = Receipt.generate(stableInput, stableOutput, action, processingTime)
            .withToolResultScan(block);

        return new GovernedToolResultScanResult(scan.getSanitized(), scan.getFindings(), scan.isBlocked(),
            scan.getReason(), receipt);
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
