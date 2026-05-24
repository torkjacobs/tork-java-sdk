package com.tork.governance;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.util.List;
import java.util.Set;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for Tork Governance Java SDK
 * Matches Python SDK test coverage
 */
public class ComprehensiveTest {

    // ========================================================================
    // PIIType Tests
    // ========================================================================

    @Nested
    @DisplayName("PIIType Tests")
    class PIITypeTests {

        @Test
        @DisplayName("PIIType.SSN should have correct redaction")
        void testSSNRedaction() {
            assertEquals("[SSN_REDACTED]", PIIType.SSN.getRedaction());
        }

        @Test
        @DisplayName("PIIType.EMAIL should have correct redaction")
        void testEmailRedaction() {
            assertEquals("[EMAIL_REDACTED]", PIIType.EMAIL.getRedaction());
        }

        @Test
        @DisplayName("PIIType.CREDIT_CARD should have correct redaction")
        void testCreditCardRedaction() {
            assertEquals("[CARD_REDACTED]", PIIType.CREDIT_CARD.getRedaction());
        }

        @Test
        @DisplayName("PIIType.PHONE should have correct redaction")
        void testPhoneRedaction() {
            assertEquals("[PHONE_REDACTED]", PIIType.PHONE.getRedaction());
        }

        @Test
        @DisplayName("PIIType.IP_ADDRESS should have correct redaction")
        void testIPAddressRedaction() {
            assertEquals("[IP_REDACTED]", PIIType.IP_ADDRESS.getRedaction());
        }

        @Test
        @DisplayName("PIIType.DATE_OF_BIRTH should have correct redaction")
        void testDOBRedaction() {
            assertEquals("[DOB_REDACTED]", PIIType.DATE_OF_BIRTH.getRedaction());
        }

        @Test
        @DisplayName("All PIIType values should be defined")
        void testAllPIITypes() {
            PIIType[] types = PIIType.values();
            assertTrue(types.length >= 6);
        }
    }

    // ========================================================================
    // GovernanceAction Tests
    // ========================================================================

    @Nested
    @DisplayName("GovernanceAction Tests")
    class GovernanceActionTests {

        @Test
        @DisplayName("ALLOW action should exist")
        void testAllowAction() {
            assertEquals(GovernanceAction.ALLOW, GovernanceAction.valueOf("ALLOW"));
        }

        @Test
        @DisplayName("DENY action should exist")
        void testDenyAction() {
            assertEquals(GovernanceAction.DENY, GovernanceAction.valueOf("DENY"));
        }

        @Test
        @DisplayName("REDACT action should exist")
        void testRedactAction() {
            assertEquals(GovernanceAction.REDACT, GovernanceAction.valueOf("REDACT"));
        }

        @Test
        @DisplayName("ESCALATE action should exist")
        void testEscalateAction() {
            assertEquals(GovernanceAction.ESCALATE, GovernanceAction.valueOf("ESCALATE"));
        }

        @Test
        @DisplayName("All GovernanceAction values should be defined")
        void testAllActions() {
            GovernanceAction[] actions = GovernanceAction.values();
            assertEquals(4, actions.length);
        }
    }

    // ========================================================================
    // PIIDetector Tests
    // ========================================================================

    @Nested
    @DisplayName("PIIDetector Tests")
    class PIIDetectorTests {

        private PIIDetector detector;

        @BeforeEach
        void setUp() {
            detector = new PIIDetector();
        }

        @Test
        @DisplayName("Should detect SSN")
        void testDetectSSN() {
            List<PIIDetector.PIIMatch> matches = detector.detect("My SSN is 123-45-6789");
            assertFalse(matches.isEmpty());
            assertTrue(matches.stream().anyMatch(m -> m.getType() == PIIType.SSN));
        }

        @Test
        @DisplayName("Should detect email")
        void testDetectEmail() {
            List<PIIDetector.PIIMatch> matches = detector.detect("Contact me at john@example.com");
            assertFalse(matches.isEmpty());
            assertTrue(matches.stream().anyMatch(m -> m.getType() == PIIType.EMAIL));
        }

        @Test
        @DisplayName("Should detect credit card")
        void testDetectCreditCard() {
            List<PIIDetector.PIIMatch> matches = detector.detect("Card: 4111-1111-1111-1111");
            assertFalse(matches.isEmpty());
            assertTrue(matches.stream().anyMatch(m -> m.getType() == PIIType.CREDIT_CARD));
        }

        @Test
        @DisplayName("Should detect phone number")
        void testDetectPhone() {
            List<PIIDetector.PIIMatch> matches = detector.detect("Call me at 555-123-4567");
            assertFalse(matches.isEmpty());
            assertTrue(matches.stream().anyMatch(m -> m.getType() == PIIType.PHONE));
        }

        @Test
        @DisplayName("Should detect IP address")
        void testDetectIPAddress() {
            List<PIIDetector.PIIMatch> matches = detector.detect("Server IP: 192.168.1.1");
            assertFalse(matches.isEmpty());
            assertTrue(matches.stream().anyMatch(m -> m.getType() == PIIType.IP_ADDRESS));
        }

        @Test
        @DisplayName("Should detect date of birth")
        void testDetectDOB() {
            List<PIIDetector.PIIMatch> matches = detector.detect("DOB: 01/15/1990");
            assertFalse(matches.isEmpty());
            assertTrue(matches.stream().anyMatch(m -> m.getType() == PIIType.DATE_OF_BIRTH));
        }

        @Test
        @DisplayName("Should not detect PII in clean text")
        void testNoPII() {
            List<PIIDetector.PIIMatch> matches = detector.detect("Hello world, no sensitive data");
            assertTrue(matches.isEmpty());
        }

        @Test
        @DisplayName("Should detect multiple PII types")
        void testMultiplePII() {
            List<PIIDetector.PIIMatch> matches = detector.detect("SSN: 123-45-6789, Email: test@test.com");
            assertEquals(2, matches.size());
        }

        @Test
        @DisplayName("Should redact SSN")
        void testRedactSSN() {
            PIIDetector.DetectionResult result = detector.detectAndRedact("My SSN is 123-45-6789");
            assertEquals("My SSN is [SSN_REDACTED]", result.getRedactedText());
        }

        @Test
        @DisplayName("Should redact email")
        void testRedactEmail() {
            PIIDetector.DetectionResult result = detector.detectAndRedact("Contact: john@example.com");
            assertEquals("Contact: [EMAIL_REDACTED]", result.getRedactedText());
        }

        @Test
        @DisplayName("Should redact credit card")
        void testRedactCreditCard() {
            PIIDetector.DetectionResult result = detector.detectAndRedact("Card: 4111-1111-1111-1111");
            assertEquals("Card: [CARD_REDACTED]", result.getRedactedText());
        }

        @Test
        @DisplayName("Should handle empty string")
        void testEmptyString() {
            List<PIIDetector.PIIMatch> matches = detector.detect("");
            assertTrue(matches.isEmpty());
        }

        @Test
        @DisplayName("Should return correct match indices")
        void testMatchIndices() {
            List<PIIDetector.PIIMatch> matches = detector.detect("SSN: 123-45-6789");
            assertFalse(matches.isEmpty());
            PIIDetector.PIIMatch match = matches.get(0);
            assertTrue(match.getStartIndex() >= 0);
            assertTrue(match.getEndIndex() > match.getStartIndex());
        }

        @Test
        @DisplayName("containsPII should return true for text with PII")
        void testContainsPIITrue() {
            assertTrue(detector.containsPII("SSN: 123-45-6789"));
        }

        @Test
        @DisplayName("containsPII should return false for text without PII")
        void testContainsPIIFalse() {
            assertFalse(detector.containsPII("Hello world"));
        }

        @Test
        @DisplayName("containsPII should check specific type")
        void testContainsPIISpecificType() {
            assertTrue(detector.containsPII("Email: test@example.com", PIIType.EMAIL));
            assertFalse(detector.containsPII("Email: test@example.com", PIIType.SSN));
        }
    }

    // ========================================================================
    // Tork Tests
    // ========================================================================

    @Nested
    @DisplayName("Tork Tests")
    class TorkTests {

        private Tork tork;

        @BeforeEach
        void setUp() {
            tork = new Tork();
        }

        @Test
        @DisplayName("Should create with default config")
        void testDefaultConfig() {
            assertEquals(GovernanceAction.REDACT, tork.getConfig().getDefaultAction());
            assertEquals("1.0.0", tork.getConfig().getPolicyVersion());
        }

        @Test
        @DisplayName("Should create with custom config")
        void testCustomConfig() {
            Tork.TorkConfig config = new Tork.TorkConfig()
                .setDefaultAction(GovernanceAction.DENY)
                .setPolicyVersion("2.0.0");
            Tork customTork = new Tork(null, config);
            assertEquals(GovernanceAction.DENY, customTork.getConfig().getDefaultAction());
            assertEquals("2.0.0", customTork.getConfig().getPolicyVersion());
        }

        @Test
        @DisplayName("Should return allow action for clean text")
        void testGovernCleanText() {
            GovernanceResult result = tork.govern("Hello world");
            assertEquals(GovernanceAction.ALLOW, result.getAction());
            assertEquals("Hello world", result.getOutput());
        }

        @Test
        @DisplayName("Should return redact action for text with PII")
        void testGovernWithPII() {
            GovernanceResult result = tork.govern("My SSN is 123-45-6789");
            assertEquals(GovernanceAction.REDACT, result.getAction());
            assertEquals("My SSN is [SSN_REDACTED]", result.getOutput());
        }

        @Test
        @DisplayName("Should include receipt in result")
        void testGovernHasReceipt() {
            GovernanceResult result = tork.govern("test");
            assertNotNull(result.getReceipt());
            assertTrue(result.getReceipt().getReceiptId().startsWith("rcpt_"));
        }

        @Test
        @DisplayName("Should track hasPII correctly")
        void testGovernHasPII() {
            GovernanceResult result = tork.govern("SSN: 123-45-6789");
            assertTrue(result.hasPII());
        }

        @Test
        @DisplayName("Receipt should have correct hashes")
        void testReceiptHashes() {
            GovernanceResult result = tork.govern("test");
            assertTrue(result.getReceipt().getInputHash().startsWith("sha256:"));
            assertTrue(result.getReceipt().getOutputHash().startsWith("sha256:"));
        }

        @Test
        @DisplayName("Should respect deny action configuration")
        void testDenyAction() {
            Tork.TorkConfig config = new Tork.TorkConfig()
                .setDefaultAction(GovernanceAction.DENY);
            Tork denyTork = new Tork(null, config);
            GovernanceResult result = denyTork.govern("SSN: 123-45-6789");
            assertEquals(GovernanceAction.DENY, result.getAction());
            assertEquals("SSN: [SSN_REDACTED]", result.getOutput()); // Output is always redacted regardless of action
        }

        @Test
        @DisplayName("Should handle multiple governs")
        void testMultipleGoverns() {
            tork.govern("test1");
            tork.govern("test2");
            assertEquals(2, tork.getTotalCalls());
        }

        @Test
        @DisplayName("containsPII should work directly")
        void testContainsPII() {
            assertTrue(tork.containsPII("SSN: 123-45-6789"));
            assertFalse(tork.containsPII("Hello world"));
        }

        @Test
        @DisplayName("containsPII with type should work")
        void testContainsPIIWithType() {
            assertTrue(tork.containsPII("Email: test@test.com", PIIType.EMAIL));
        }
    }

    // ========================================================================
    // Stats Tests
    // ========================================================================

    @Nested
    @DisplayName("Stats Tests")
    class StatsTests {

        private Tork tork;

        @BeforeEach
        void setUp() {
            tork = new Tork();
        }

        @Test
        @DisplayName("Should return zero stats initially")
        void testInitialStats() {
            assertEquals(0, tork.getTotalCalls());
            assertEquals(0, tork.getTotalPIIDetected());
        }

        @Test
        @DisplayName("Should track total calls")
        void testTrackCalls() {
            tork.govern("test");
            tork.govern("test2");
            assertEquals(2, tork.getTotalCalls());
        }

        @Test
        @DisplayName("Should track PII detected")
        void testTrackPIIDetected() {
            tork.govern("SSN: 123-45-6789");
            tork.govern("clean text");
            assertEquals(1, tork.getTotalPIIDetected());
        }

        @Test
        @DisplayName("Should calculate average processing time")
        void testAverageProcessingTime() {
            tork.govern("test");
            assertTrue(tork.getAverageProcessingTimeNanos() >= 0);
        }

        @Test
        @DisplayName("Should reset stats")
        void testResetStats() {
            tork.govern("SSN: 123-45-6789");
            tork.govern("test");
            tork.resetStats();
            assertEquals(0, tork.getTotalCalls());
            assertEquals(0, tork.getTotalPIIDetected());
        }
    }

    // ========================================================================
    // Receipt Tests
    // ========================================================================

    @Nested
    @DisplayName("Receipt Tests")
    class ReceiptTests {

        private Tork tork;

        @BeforeEach
        void setUp() {
            tork = new Tork();
        }

        @Test
        @DisplayName("Should have unique receipt IDs")
        void testUniqueReceiptIDs() {
            GovernanceResult result1 = tork.govern("test1");
            GovernanceResult result2 = tork.govern("test2");
            assertNotEquals(result1.getReceipt().getReceiptId(), result2.getReceipt().getReceiptId());
        }

        @Test
        @DisplayName("Should have timestamp")
        void testReceiptTimestamp() {
            GovernanceResult result = tork.govern("test");
            assertNotNull(result.getReceipt().getTimestamp());
        }

        @Test
        @DisplayName("Should have input hash")
        void testReceiptInputHash() {
            GovernanceResult result = tork.govern("test");
            assertTrue(result.getReceipt().getInputHash().startsWith("sha256:"));
        }

        @Test
        @DisplayName("Should have output hash")
        void testReceiptOutputHash() {
            GovernanceResult result = tork.govern("test");
            assertTrue(result.getReceipt().getOutputHash().startsWith("sha256:"));
        }

        @Test
        @DisplayName("Should have action")
        void testReceiptAction() {
            GovernanceResult result = tork.govern("test");
            assertNotNull(result.getReceipt().getAction());
        }

        @Test
        @DisplayName("Should have processing time")
        void testReceiptProcessingTime() {
            GovernanceResult result = tork.govern("test");
            assertTrue(result.getReceipt().getProcessingTimeNanos() >= 0);
        }
    }

    // ========================================================================
    // Edge Cases Tests
    // ========================================================================

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        private Tork tork;

        @BeforeEach
        void setUp() {
            tork = new Tork();
        }

        @Test
        @DisplayName("Should handle long text")
        void testLongText() {
            String longText = "A".repeat(100000);
            GovernanceResult result = tork.govern(longText);
            assertEquals(GovernanceAction.ALLOW, result.getAction());
        }

        @Test
        @DisplayName("Should handle unicode")
        void testUnicode() {
            GovernanceResult result = tork.govern("Hello \u4e16\u754c, SSN: 123-45-6789");
            assertTrue(result.hasPII());
        }

        @Test
        @DisplayName("Should handle special characters")
        void testSpecialChars() {
            GovernanceResult result = tork.govern("Special chars: !@#$%^&*()");
            assertEquals(GovernanceAction.ALLOW, result.getAction());
        }

        @Test
        @DisplayName("Should handle newlines")
        void testNewlines() {
            GovernanceResult result = tork.govern("Line1\nLine2\nSSN: 123-45-6789");
            assertTrue(result.hasPII());
        }

        @Test
        @DisplayName("Should handle tabs")
        void testTabs() {
            GovernanceResult result = tork.govern("Tab\there\tSSN: 123-45-6789");
            assertTrue(result.hasPII());
        }

        @Test
        @DisplayName("Should handle repeated governs")
        void testRepeatedGoverns() {
            for (int i = 0; i < 100; i++) {
                GovernanceResult result = tork.govern("Test " + i);
                assertNotNull(result.getReceipt());
            }
            assertEquals(100, tork.getTotalCalls());
        }

        @Test
        @DisplayName("Should handle empty string")
        void testEmptyString() {
            GovernanceResult result = tork.govern("");
            assertEquals(GovernanceAction.ALLOW, result.getAction());
        }

        @Test
        @DisplayName("Should handle null input")
        void testNullInput() {
            GovernanceResult result = tork.govern(null);
            assertEquals(GovernanceAction.ALLOW, result.getAction());
        }

        @Test
        @DisplayName("Should handle adjacent PII")
        void testAdjacentPII() {
            GovernanceResult result = tork.govern("123-45-6789 987-65-4321");
            assertTrue(result.hasPII());
        }

        @Test
        @DisplayName("Should handle multiple PII instances")
        void testMultiplePIIInstances() {
            GovernanceResult result = tork.govern("SSN: 123-45-6789, Another: 987-65-4321");
            assertTrue(result.hasPII());
            assertTrue(result.getOutput().contains("[SSN_REDACTED]"));
        }
    }
}
