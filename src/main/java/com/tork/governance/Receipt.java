package com.tork.governance;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * Cryptographic receipt for governance operations.
 * Provides an audit trail with SHA-256 hashes of input and output.
 */
public class Receipt {
    private final String receiptId;
    private final String timestamp;
    private final String inputHash;
    private final String outputHash;
    private final GovernanceAction action;
    private final String policyVersion;
    private final long processingTimeNanos;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String DEFAULT_POLICY_VERSION = "1.0.0";

    /**
     * Create a new receipt with all fields.
     */
    public Receipt(String receiptId, String timestamp, String inputHash,
                   String outputHash, GovernanceAction action,
                   String policyVersion, long processingTimeNanos) {
        this.receiptId = receiptId;
        this.timestamp = timestamp;
        this.inputHash = inputHash;
        this.outputHash = outputHash;
        this.action = action;
        this.policyVersion = policyVersion;
        this.processingTimeNanos = processingTimeNanos;
    }

    /**
     * Generate a new receipt for a governance operation.
     *
     * @param input the original input text
     * @param output the governed output text
     * @param action the governance action taken
     * @return a new Receipt instance
     */
    public static Receipt generate(String input, String output, GovernanceAction action) {
        return generate(input, output, action, 0);
    }

    /**
     * Generate a new receipt with processing time.
     *
     * @param input the original input text
     * @param output the governed output text
     * @param action the governance action taken
     * @param processingTimeNanos processing time in nanoseconds
     * @return a new Receipt instance
     */
    public static Receipt generate(String input, String output, GovernanceAction action,
                                   long processingTimeNanos) {
        return new Receipt(
            generateReceiptId(),
            Instant.now().toString(),
            hashText(input),
            hashText(output),
            action,
            DEFAULT_POLICY_VERSION,
            processingTimeNanos
        );
    }

    /**
     * Generate a unique receipt ID.
     * @return a unique receipt ID string
     */
    public static String generateReceiptId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        String hex = bytesToHex(bytes);
        return "rcpt_" + hex;
    }

    /**
     * Hash text using SHA-256.
     * @param text the text to hash
     * @return the hash string prefixed with "sha256:"
     */
    public static String hashText(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Verify that the input hash matches a given text.
     * @param text the text to verify
     * @return true if the hash matches
     */
    public boolean verifyInput(String text) {
        return inputHash.equals(hashText(text));
    }

    /**
     * Verify that the output hash matches a given text.
     * @param text the text to verify
     * @return true if the hash matches
     */
    public boolean verifyOutput(String text) {
        return outputHash.equals(hashText(text));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Getters
    public String getReceiptId() { return receiptId; }
    public String getTimestamp() { return timestamp; }
    public String getInputHash() { return inputHash; }
    public String getOutputHash() { return outputHash; }
    public GovernanceAction getAction() { return action; }
    public String getPolicyVersion() { return policyVersion; }
    public long getProcessingTimeNanos() { return processingTimeNanos; }

    @Override
    public String toString() {
        return "Receipt{" +
                "receiptId='" + receiptId + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", action=" + action +
                ", policyVersion='" + policyVersion + '\'' +
                '}';
    }
}
