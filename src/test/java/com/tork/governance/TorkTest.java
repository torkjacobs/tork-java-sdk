package com.tork.governance;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the main Tork class.
 */
class TorkTest {

    private Tork tork;

    @BeforeEach
    void setUp() {
        tork = new Tork();
    }

    @Test
    @DisplayName("Clean input passes through unchanged")
    void testCleanInput() {
        String input = "Hello, this is a test message with no PII.";
        GovernanceResult result = tork.govern(input);

        assertEquals(GovernanceAction.ALLOW, result.getAction());
        assertEquals(input, result.getOutput());
        assertFalse(result.hasPII());
        assertTrue(result.getMatches().isEmpty());
        assertNotNull(result.getReceipt());
    }

    @Test
    @DisplayName("SSN is detected and redacted")
    void testSSNDetection() {
        String input = "My SSN is 123-45-6789";
        GovernanceResult result = tork.govern(input);

        assertEquals(GovernanceAction.REDACT, result.getAction());
        assertEquals("My SSN is [SSN_REDACTED]", result.getOutput());
        assertTrue(result.hasPII());
        assertTrue(result.getPiiTypes().contains(PIIType.SSN));
    }

    @Test
    @DisplayName("Email is detected and redacted")
    void testEmailDetection() {
        String input = "Contact me at test@example.com";
        GovernanceResult result = tork.govern(input);

        assertEquals(GovernanceAction.REDACT, result.getAction());
        assertEquals("Contact me at [EMAIL_REDACTED]", result.getOutput());
        assertTrue(result.hasPII());
        assertTrue(result.getPiiTypes().contains(PIIType.EMAIL));
    }

    @Test
    @DisplayName("Phone number is detected and redacted")
    void testPhoneDetection() {
        String input = "Call me at 555-123-4567";
        GovernanceResult result = tork.govern(input);

        assertEquals(GovernanceAction.REDACT, result.getAction());
        assertTrue(result.getOutput().contains("[PHONE_REDACTED]"));
        assertTrue(result.hasPII());
        assertTrue(result.getPiiTypes().contains(PIIType.PHONE));
    }

    @Test
    @DisplayName("Credit card is detected and redacted")
    void testCreditCardDetection() {
        String input = "Card number: 4111-1111-1111-1111";
        GovernanceResult result = tork.govern(input);

        assertEquals(GovernanceAction.REDACT, result.getAction());
        assertEquals("Card number: [CARD_REDACTED]", result.getOutput());
        assertTrue(result.hasPII());
        assertTrue(result.getPiiTypes().contains(PIIType.CREDIT_CARD));
    }

    @Test
    @DisplayName("Multiple PII types are detected and redacted")
    void testMultiplePIITypes() {
        String input = "Email: user@test.com, SSN: 123-45-6789, Phone: 555-123-4567";
        GovernanceResult result = tork.govern(input);

        assertEquals(GovernanceAction.REDACT, result.getAction());
        assertTrue(result.getOutput().contains("[EMAIL_REDACTED]"));
        assertTrue(result.getOutput().contains("[SSN_REDACTED]"));
        assertTrue(result.getOutput().contains("[PHONE_REDACTED]"));
        assertTrue(result.hasPII());
        assertEquals(3, result.getPiiTypes().size());
    }

    @Test
    @DisplayName("Receipt is generated with valid ID")
    void testReceiptGeneration() {
        String input = "Test input 123-45-6789";
        GovernanceResult result = tork.govern(input);

        Receipt receipt = result.getReceipt();
        assertNotNull(receipt);
        assertTrue(receipt.getReceiptId().startsWith("rcpt_"));
        assertNotNull(receipt.getTimestamp());
        assertTrue(receipt.getInputHash().startsWith("sha256:"));
        assertTrue(receipt.getOutputHash().startsWith("sha256:"));
        assertEquals(result.getAction(), receipt.getAction());
    }

    @Test
    @DisplayName("Receipt hashes are different for input and output with PII")
    void testReceiptHashesDifferent() {
        String input = "SSN: 123-45-6789";
        GovernanceResult result = tork.govern(input);

        Receipt receipt = result.getReceipt();
        assertNotEquals(receipt.getInputHash(), receipt.getOutputHash());
    }

    @Test
    @DisplayName("Receipt hashes are same for clean input")
    void testReceiptHashesSame() {
        String input = "Clean input with no PII";
        GovernanceResult result = tork.govern(input);

        Receipt receipt = result.getReceipt();
        assertEquals(receipt.getInputHash(), receipt.getOutputHash());
    }

    @Test
    @DisplayName("Empty input is handled")
    void testEmptyInput() {
        GovernanceResult result = tork.govern("");

        assertEquals(GovernanceAction.ALLOW, result.getAction());
        assertEquals("", result.getOutput());
        assertFalse(result.hasPII());
    }

    @Test
    @DisplayName("Null input is handled")
    void testNullInput() {
        GovernanceResult result = tork.govern(null);

        assertEquals(GovernanceAction.ALLOW, result.getAction());
        assertEquals("", result.getOutput());
        assertFalse(result.hasPII());
    }

    @Test
    @DisplayName("containsPII returns true for PII")
    void testContainsPII() {
        assertTrue(tork.containsPII("test@example.com"));
        assertTrue(tork.containsPII("123-45-6789"));
        assertFalse(tork.containsPII("Hello world"));
    }

    @Test
    @DisplayName("containsPII with specific type works")
    void testContainsPIIWithType() {
        assertTrue(tork.containsPII("test@example.com", PIIType.EMAIL));
        assertFalse(tork.containsPII("test@example.com", PIIType.SSN));
    }

    @Test
    @DisplayName("Statistics are tracked")
    void testStatistics() {
        tork.resetStats();

        tork.govern("Clean input");
        tork.govern("SSN: 123-45-6789");
        tork.govern("Email: test@test.com");

        assertEquals(3, tork.getTotalCalls());
        assertEquals(2, tork.getTotalPIIDetected());
        assertTrue(tork.getAverageProcessingTimeNanos() > 0);
    }

    @Test
    @DisplayName("Tork with API key")
    void testWithApiKey() {
        Tork torkWithKey = new Tork("test-api-key");
        assertEquals("test-api-key", torkWithKey.getApiKey());

        GovernanceResult result = torkWithKey.govern("test@example.com");
        assertEquals(GovernanceAction.REDACT, result.getAction());
    }

    @Test
    @DisplayName("Tork with custom config")
    void testWithConfig() {
        Tork.TorkConfig config = new Tork.TorkConfig()
            .setDefaultAction(GovernanceAction.DENY)
            .setPolicyVersion("2.0.0");

        Tork customTork = new Tork(null, config);
        GovernanceResult result = customTork.govern("test@example.com");

        assertEquals(GovernanceAction.DENY, result.getAction());
    }
}
