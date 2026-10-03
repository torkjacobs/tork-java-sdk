package com.tork.governance;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Agent telemetry fields: agent_id, agent_role, session_id, session_turn. */
class SessionContextTest {

    @Test
    @DisplayName("All four fields appear with snake_case keys; session_turn is an integer")
    void testAllFieldsSet() {
        Map<String, Object> f = new SessionContext("agent-1", "planner", "sess-9", 3).toRequestFields();
        assertEquals(Arrays.asList("agent_id", "agent_role", "session_id", "session_turn"),
            Arrays.asList(f.keySet().toArray()));
        assertEquals("agent-1", f.get("agent_id"));
        assertEquals("planner", f.get("agent_role"));
        assertEquals("sess-9", f.get("session_id"));
        assertEquals(Integer.valueOf(3), f.get("session_turn"));
        assertTrue(f.get("session_turn") instanceof Integer);
    }

    @Test
    @DisplayName("Unset fields are omitted, not sent as null")
    void testUnsetFieldsOmitted() {
        Map<String, Object> f = new SessionContext(null, "worker", null, 0).toRequestFields();
        assertEquals(2, f.size());
        assertEquals("worker", f.get("agent_role"));
        assertEquals(Integer.valueOf(0), f.get("session_turn"));
        assertFalse(f.containsKey("agent_id"));
        assertFalse(f.containsKey("session_id"));
    }

    @Test
    @DisplayName("A context with nothing set yields no fields")
    void testEmptyContext() {
        assertTrue(new SessionContext(null, null, null, null).toRequestFields().isEmpty());
        assertTrue(new SessionContext("", "", "", null).toRequestFields().isEmpty());
    }

    @Test
    @DisplayName("govern(input, context) carries the context on the result")
    void testGovernPassesContextThrough() {
        Tork tork = new Tork();
        SessionContext ctx = new SessionContext("a", "judge", "s", 2);
        GovernanceResult r = tork.govern("My email is test@example.com", ctx);
        assertSame(ctx, r.getSessionContext());
        assertEquals("My email is [EMAIL_REDACTED]", r.getOutput());
    }

    @Test
    @DisplayName("Without a context the result carries none")
    void testGovernWithoutContext() {
        Tork tork = new Tork();
        assertNull(tork.govern("hello").getSessionContext());
        assertNull(tork.govern("hello", (SessionContext) null).getSessionContext());
        assertNull(tork.govern("hello", Collections.emptyList(), null).getSessionContext());
    }

    @Test
    @DisplayName("The region/industry overload passes the context through too")
    void testFullOverload() {
        SessionContext ctx = new SessionContext("a", null, null, 1);
        GovernanceResult r = new Tork().govern("hi", Arrays.asList("ae"), "finance", ctx);
        assertSame(ctx, r.getSessionContext());
    }

    @Test
    @DisplayName("The returned fields map is read-only")
    void testFieldsReadOnly() {
        Map<String, Object> f = new SessionContext("a", null, null, null).toRequestFields();
        assertThrows(UnsupportedOperationException.class, () -> f.put("x", 1));
    }
}
