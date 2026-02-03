package com.tork.governance;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PIIDetector class.
 */
class PIIDetectorTest {

    private PIIDetector detector;

    @BeforeEach
    void setUp() {
        detector = new PIIDetector();
    }

    @Test
    @DisplayName("Detect SSN pattern")
    void testDetectSSN() {
        List<PIIDetector.PIIMatch> matches = detector.detect("SSN: 123-45-6789");

        assertEquals(1, matches.size());
        assertEquals(PIIType.SSN, matches.get(0).getType());
        assertEquals("123-45-6789", matches.get(0).getValue());
    }

    @Test
    @DisplayName("Detect email pattern")
    void testDetectEmail() {
        List<PIIDetector.PIIMatch> matches = detector.detect("Email: john.doe@example.com");

        assertEquals(1, matches.size());
        assertEquals(PIIType.EMAIL, matches.get(0).getType());
        assertEquals("john.doe@example.com", matches.get(0).getValue());
    }

    @Test
    @DisplayName("Detect various email formats")
    void testDetectVariousEmails() {
        String[] emails = {
            "simple@example.com",
            "very.common@example.com",
            "disposable.style.email.with+symbol@example.com",
            "user.name+tag@example.co.uk"
        };

        for (String email : emails) {
            List<PIIDetector.PIIMatch> matches = detector.detect(email);
            assertFalse(matches.isEmpty(), "Should detect: " + email);
            assertEquals(PIIType.EMAIL, matches.get(0).getType());
        }
    }

    @Test
    @DisplayName("Detect phone number patterns")
    void testDetectPhone() {
        String[] phones = {
            "555-123-4567",
            "(555) 123-4567",
            "555.123.4567",
            "+1 555-123-4567",
            "1-555-123-4567"
        };

        for (String phone : phones) {
            assertTrue(detector.containsPII(phone, PIIType.PHONE),
                "Should detect phone: " + phone);
        }
    }

    @Test
    @DisplayName("Detect credit card patterns")
    void testDetectCreditCard() {
        String[] cards = {
            "4111-1111-1111-1111",
            "4111 1111 1111 1111",
            "4111111111111111"
        };

        for (String card : cards) {
            assertTrue(detector.containsPII(card, PIIType.CREDIT_CARD),
                "Should detect card: " + card);
        }
    }

    @Test
    @DisplayName("Detect IP address")
    void testDetectIP() {
        List<PIIDetector.PIIMatch> matches = detector.detect("Server IP: 192.168.1.1");

        assertEquals(1, matches.size());
        assertEquals(PIIType.IP_ADDRESS, matches.get(0).getType());
        assertEquals("192.168.1.1", matches.get(0).getValue());
    }

    @Test
    @DisplayName("Detect date of birth")
    void testDetectDOB() {
        List<PIIDetector.PIIMatch> matches = detector.detect("DOB: 12/25/1990");

        assertEquals(1, matches.size());
        assertEquals(PIIType.DATE_OF_BIRTH, matches.get(0).getType());
        assertEquals("12/25/1990", matches.get(0).getValue());
    }

    @Test
    @DisplayName("Detect multiple PII types")
    void testDetectMultiple() {
        String text = "Contact: john@example.com, SSN: 123-45-6789, Phone: 555-123-4567";
        List<PIIDetector.PIIMatch> matches = detector.detect(text);

        assertTrue(matches.size() >= 3);

        boolean hasEmail = matches.stream().anyMatch(m -> m.getType() == PIIType.EMAIL);
        boolean hasSSN = matches.stream().anyMatch(m -> m.getType() == PIIType.SSN);
        boolean hasPhone = matches.stream().anyMatch(m -> m.getType() == PIIType.PHONE);

        assertTrue(hasEmail);
        assertTrue(hasSSN);
        assertTrue(hasPhone);
    }

    @Test
    @DisplayName("No PII in clean text")
    void testNoPII() {
        List<PIIDetector.PIIMatch> matches = detector.detect(
            "This is a clean text with no personally identifiable information.");

        assertTrue(matches.isEmpty());
    }

    @Test
    @DisplayName("Redact PII in text")
    void testRedact() {
        String text = "Email: test@example.com, SSN: 123-45-6789";
        List<PIIDetector.PIIMatch> matches = detector.detect(text);
        String redacted = detector.redact(text, matches);

        assertEquals("Email: [EMAIL_REDACTED], SSN: [SSN_REDACTED]", redacted);
        assertFalse(redacted.contains("test@example.com"));
        assertFalse(redacted.contains("123-45-6789"));
    }

    @Test
    @DisplayName("detectAndRedact returns full result")
    void testDetectAndRedact() {
        String text = "Card: 4111-1111-1111-1111, Email: user@test.com";
        PIIDetector.DetectionResult result = detector.detectAndRedact(text);

        assertTrue(result.hasPII());
        assertEquals(2, result.getCount());
        assertTrue(result.getTypes().contains(PIIType.CREDIT_CARD));
        assertTrue(result.getTypes().contains(PIIType.EMAIL));
        assertTrue(result.getRedactedText().contains("[CARD_REDACTED]"));
        assertTrue(result.getRedactedText().contains("[EMAIL_REDACTED]"));
    }

    @Test
    @DisplayName("containsPII returns correct boolean")
    void testContainsPII() {
        assertTrue(detector.containsPII("test@example.com"));
        assertTrue(detector.containsPII("123-45-6789"));
        assertFalse(detector.containsPII("Hello, World!"));
    }

    @Test
    @DisplayName("containsPII with type returns correct boolean")
    void testContainsPIIWithType() {
        String text = "Email: test@example.com";

        assertTrue(detector.containsPII(text, PIIType.EMAIL));
        assertFalse(detector.containsPII(text, PIIType.SSN));
        assertFalse(detector.containsPII(text, PIIType.PHONE));
    }

    @Test
    @DisplayName("Match indices are correct")
    void testMatchIndices() {
        String text = "SSN: 123-45-6789";
        List<PIIDetector.PIIMatch> matches = detector.detect(text);

        assertEquals(1, matches.size());
        PIIDetector.PIIMatch match = matches.get(0);

        assertEquals(5, match.getStartIndex());
        assertEquals(16, match.getEndIndex());
        assertEquals("123-45-6789", text.substring(match.getStartIndex(), match.getEndIndex()));
    }

    @Test
    @DisplayName("Empty string returns no matches")
    void testEmptyString() {
        List<PIIDetector.PIIMatch> matches = detector.detect("");
        assertTrue(matches.isEmpty());
    }
}
