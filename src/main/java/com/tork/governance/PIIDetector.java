package com.tork.governance;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects and redacts PII (Personally Identifiable Information) in text.
 * Uses regex patterns for various PII types.
 *
 * <p>PATTERNS covers the full Tier 1 basic vocabulary (10 types), ported
 * regex-source-verbatim from tork-js-sdk/src/pii.ts's {@code PII_PATTERNS},
 * in the same declaration order (ssn, credit_card, email, phone, address,
 * ip_address, date_of_birth, passport, drivers_license, bank_account) so
 * that {@link #detect}/{@link #detectAndRedact}'s sequential per-type
 * redaction matches the JS/Go SDKs' behavior: later patterns (notably
 * {@code bank_account}'s broad {@code \d{8,17}}) only see text already
 * redacted by earlier, more specific patterns. {@link PIIType}'s enum
 * declaration order mirrors this same order for the same reason (an
 * {@link EnumMap} iterates in enum-declaration order).</p>
 *
 * <p>Parity discipline (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS):
 * every {@link PIIType} constant MUST have a corresponding entry here. See
 * {@code PIIDetectorTest#testEveryDeclaredPIITypeHasAPattern}.</p>
 */
public class PIIDetector {

    private static final Map<PIIType, Pattern> PATTERNS = new EnumMap<>(PIIType.class);

    static {
        // Social Security Number: XXX-XX-XXXX
        PATTERNS.put(PIIType.SSN, Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"));

        // Credit card number (16 digits with optional separators)
        PATTERNS.put(PIIType.CREDIT_CARD, Pattern.compile(
            "\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b"));

        // Email address
        PATTERNS.put(PIIType.EMAIL, Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"));

        // Phone number (US formats)
        PATTERNS.put(PIIType.PHONE, Pattern.compile(
            "\\b(?:\\+?1[-.]?\\s?)?\\(?\\d{3}\\)?[-.]?\\s?\\d{3}[-.]?\\s?\\d{4}\\b"));

        // Street address (case-insensitive: JS source carries the `i` flag)
        PATTERNS.put(PIIType.ADDRESS, Pattern.compile(
            "\\b\\d{1,5}\\s+\\w+(?:\\s+\\w+)*\\s+(?:Street|St|Avenue|Ave|Road|Rd|" +
            "Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\\b",
            Pattern.CASE_INSENSITIVE));

        // IP address
        PATTERNS.put(PIIType.IP_ADDRESS, Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
            "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"));

        // Date of birth (MM/DD/YYYY)
        PATTERNS.put(PIIType.DATE_OF_BIRTH, Pattern.compile(
            "\\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\\d|3[01])/(?:19|20)\\d{2}\\b"));

        // Passport number (1-2 uppercase letters + 6-9 digits)
        PATTERNS.put(PIIType.PASSPORT, Pattern.compile("\\b[A-Z]{1,2}\\d{6,9}\\b"));

        // Driver's license number (1 uppercase letter + 7-14 digits)
        PATTERNS.put(PIIType.DRIVERS_LICENSE, Pattern.compile("\\b[A-Z]\\d{7,14}\\b"));

        // Bank account number (8-17 digits) -- deliberately last: broad and
        // greedy, so it only redacts digit runs no earlier, more specific
        // pattern already claimed.
        PATTERNS.put(PIIType.BANK_ACCOUNT, Pattern.compile("\\b\\d{8,17}\\b"));
    }

    /**
     * The live pattern table, keyed by {@link PIIType}. Exposed for parity
     * testing (every declared {@link PIIType} must have an entry here) and
     * for reuse by other on-device scanners (e.g. tool-result scanning) so
     * there is exactly one detector implementation, not a second copy of
     * these patterns.
     *
     * @return an unmodifiable view of the pattern table
     */
    public static Map<PIIType, Pattern> getPatterns() {
        return Collections.unmodifiableMap(PATTERNS);
    }

    /**
     * Represents a match of PII in text.
     */
    public static class PIIMatch {
        private final PIIType type;
        private final String value;
        private final int startIndex;
        private final int endIndex;

        public PIIMatch(PIIType type, String value, int startIndex, int endIndex) {
            this.type = type;
            this.value = value;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        public PIIType getType() { return type; }
        public String getValue() { return value; }
        public int getStartIndex() { return startIndex; }
        public int getEndIndex() { return endIndex; }

        @Override
        public String toString() {
            return "PIIMatch{type=" + type + ", value='" + value + "', " +
                   "start=" + startIndex + ", end=" + endIndex + "}";
        }
    }

    /**
     * Result of PII detection.
     */
    public static class DetectionResult {
        private final boolean hasPII;
        private final Set<PIIType> types;
        private final List<PIIMatch> matches;
        private final String redactedText;

        public DetectionResult(boolean hasPII, Set<PIIType> types,
                               List<PIIMatch> matches, String redactedText) {
            this.hasPII = hasPII;
            this.types = types;
            this.matches = matches;
            this.redactedText = redactedText;
        }

        public boolean hasPII() { return hasPII; }
        public Set<PIIType> getTypes() { return types; }
        public List<PIIMatch> getMatches() { return matches; }
        public String getRedactedText() { return redactedText; }
        public int getCount() { return matches.size(); }
    }

    /**
     * Detect all PII in the given text.
     *
     * @param text the text to scan
     * @return list of PII matches found
     */
    public List<PIIMatch> detect(String text) {
        List<PIIMatch> matches = new ArrayList<>();

        for (Map.Entry<PIIType, Pattern> entry : PATTERNS.entrySet()) {
            PIIType type = entry.getKey();
            Pattern pattern = entry.getValue();
            Matcher matcher = pattern.matcher(text);

            while (matcher.find()) {
                matches.add(new PIIMatch(
                    type,
                    "[REDACTED]",
                    matcher.start(),
                    matcher.end()
                ));
            }
        }

        return matches;
    }

    /**
     * Detect PII and return a full detection result with redacted text.
     *
     * @param text the text to scan
     * @return detection result with matches and redacted text
     */
    public DetectionResult detectAndRedact(String text) {
        List<PIIMatch> matches = detect(text);
        Set<PIIType> types = new HashSet<>();
        String redactedText = text;

        for (PIIMatch match : matches) {
            types.add(match.getType());
        }

        // Redact each PII type
        for (Map.Entry<PIIType, Pattern> entry : PATTERNS.entrySet()) {
            PIIType type = entry.getKey();
            Pattern pattern = entry.getValue();
            redactedText = pattern.matcher(redactedText).replaceAll(type.getRedaction());
        }

        return new DetectionResult(!matches.isEmpty(), types, matches, redactedText);
    }

    /**
     * Redact PII in text based on provided matches.
     *
     * @param text the original text
     * @param matches the PII matches to redact
     * @return the redacted text
     */
    public String redact(String text, List<PIIMatch> matches) {
        if (matches.isEmpty()) {
            return text;
        }

        String result = text;
        for (Map.Entry<PIIType, Pattern> entry : PATTERNS.entrySet()) {
            PIIType type = entry.getKey();
            Pattern pattern = entry.getValue();
            result = pattern.matcher(result).replaceAll(type.getRedaction());
        }

        return result;
    }

    /**
     * Check if text contains any PII.
     *
     * @param text the text to check
     * @return true if PII is detected
     */
    public boolean containsPII(String text) {
        for (Pattern pattern : PATTERNS.values()) {
            if (pattern.matcher(text).find()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if text contains a specific type of PII.
     *
     * @param text the text to check
     * @param type the PII type to look for
     * @return true if the specified PII type is detected
     */
    public boolean containsPII(String text, PIIType type) {
        Pattern pattern = PATTERNS.get(type);
        return pattern != null && pattern.matcher(text).find();
    }
}
