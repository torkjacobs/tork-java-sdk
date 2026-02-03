package com.tork.governance.middleware;

import com.tork.governance.GovernanceAction;
import com.tork.governance.GovernanceResult;
import com.tork.governance.Tork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SpringBootFilter.
 * Note: These are unit tests for the filter logic.
 * Integration tests would require a full servlet container.
 */
class SpringBootFilterTest {

    private SpringBootFilter filter;
    private Tork tork;

    @BeforeEach
    void setUp() {
        tork = new Tork();
        filter = new SpringBootFilter(tork);
    }

    @Test
    @DisplayName("Filter creates with default Tork")
    void testDefaultConstructor() {
        SpringBootFilter defaultFilter = new SpringBootFilter();
        assertNotNull(defaultFilter);
    }

    @Test
    @DisplayName("Filter creates with API key")
    void testApiKeyConstructor() {
        SpringBootFilter keyFilter = new SpringBootFilter("test-key");
        assertNotNull(keyFilter);
    }

    @Test
    @DisplayName("Filter creates with custom Tork")
    void testTorkConstructor() {
        SpringBootFilter torkFilter = new SpringBootFilter(tork);
        assertNotNull(torkFilter);
    }

    @Test
    @DisplayName("setProtectedPaths returns filter for chaining")
    void testSetProtectedPaths() {
        SpringBootFilter result = filter.setProtectedPaths("/api/", "/v1/");
        assertSame(filter, result);
    }

    @Test
    @DisplayName("setExcludedPaths returns filter for chaining")
    void testSetExcludedPaths() {
        SpringBootFilter result = filter.setExcludedPaths("/health", "/metrics");
        assertSame(filter, result);
    }

    @Test
    @DisplayName("Underlying Tork governs correctly")
    void testUnderlyingTork() {
        GovernanceResult result = tork.govern("Email: test@example.com");

        assertEquals(GovernanceAction.REDACT, result.getAction());
        assertEquals("Email: [EMAIL_REDACTED]", result.getOutput());
        assertTrue(result.hasPII());
    }

    @Test
    @DisplayName("Clean input passes through unchanged")
    void testCleanInput() {
        GovernanceResult result = tork.govern("Hello, this is clean text");

        assertEquals(GovernanceAction.ALLOW, result.getAction());
        assertEquals("Hello, this is clean text", result.getOutput());
        assertFalse(result.hasPII());
    }

    @Test
    @DisplayName("Multiple PII types are redacted")
    void testMultiplePII() {
        String input = "Email: user@test.com, SSN: 123-45-6789";
        GovernanceResult result = tork.govern(input);

        assertEquals(GovernanceAction.REDACT, result.getAction());
        assertTrue(result.getOutput().contains("[EMAIL_REDACTED]"));
        assertTrue(result.getOutput().contains("[SSN_REDACTED]"));
        assertEquals(2, result.getPiiTypes().size());
    }

    @Test
    @DisplayName("Receipt is included in result")
    void testReceiptIncluded() {
        GovernanceResult result = tork.govern("test@example.com");

        assertNotNull(result.getReceipt());
        assertTrue(result.getReceipt().getReceiptId().startsWith("rcpt_"));
        assertNotNull(result.getReceipt().getTimestamp());
    }

    @Test
    @DisplayName("isAllowed returns true for ALLOW and REDACT")
    void testIsAllowed() {
        GovernanceResult allowResult = tork.govern("Clean text");
        GovernanceResult redactResult = tork.govern("test@example.com");

        assertTrue(allowResult.isAllowed());
        assertTrue(redactResult.isAllowed());
    }

    @Test
    @DisplayName("isDenied returns true for DENY action")
    void testIsDenied() {
        // Configure Tork with DENY as default action
        Tork.TorkConfig config = new Tork.TorkConfig()
            .setDefaultAction(GovernanceAction.DENY);
        Tork denyTork = new Tork(null, config);

        GovernanceResult result = denyTork.govern("test@example.com");

        assertTrue(result.isDenied());
        assertFalse(result.isAllowed());
    }
}
