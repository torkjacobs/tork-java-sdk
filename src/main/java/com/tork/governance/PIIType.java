package com.tork.governance;

/**
 * Enumeration of PII (Personally Identifiable Information) types
 * that can be detected and redacted by Tork.
 */
public enum PIIType {
    /** Social Security Number (format: XXX-XX-XXXX) */
    SSN("ssn", "[SSN_REDACTED]"),

    /** Email address */
    EMAIL("email", "[EMAIL_REDACTED]"),

    /** Phone number (US formats) */
    PHONE("phone", "[PHONE_REDACTED]"),

    /** Credit card number (16 digits) */
    CREDIT_CARD("credit_card", "[CARD_REDACTED]"),

    /** IP address */
    IP_ADDRESS("ip_address", "[IP_REDACTED]"),

    /** Date of birth (MM/DD/YYYY format) */
    DATE_OF_BIRTH("date_of_birth", "[DOB_REDACTED]");

    private final String code;
    private final String redaction;

    PIIType(String code, String redaction) {
        this.code = code;
        this.redaction = redaction;
    }

    /**
     * Get the code identifier for this PII type.
     * @return the code string
     */
    public String getCode() {
        return code;
    }

    /**
     * Get the redaction placeholder for this PII type.
     * @return the redaction string
     */
    public String getRedaction() {
        return redaction;
    }

    /**
     * Find a PIIType by its code.
     * @param code the code to search for
     * @return the matching PIIType or null if not found
     */
    public static PIIType fromCode(String code) {
        for (PIIType type : values()) {
            if (type.code.equals(code)) {
                return type;
            }
        }
        return null;
    }
}
