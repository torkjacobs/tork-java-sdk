package com.tork.governance;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Agent/session context for multi-agent governance tracking.
 *
 * <p>All fields are optional. Fields that are set travel with the governance
 * call: {@link GovernanceResult#getSessionContext()} returns them, and
 * {@link #toRequestFields()} gives the snake_case wire fields
 * ({@code agent_id}, {@code agent_role}, {@code session_id},
 * {@code session_turn}) for the governance API request body. Fields that are
 * not set are omitted, never sent as null.</p>
 */
public class SessionContext {
    private final String agentId;
    private final String agentRole;
    private final String sessionId;
    private final Integer sessionTurn;

    /**
     * Create a new session context.
     *
     * @param agentId    identifier for the agent making the call (nullable)
     * @param agentRole  role of the agent: "planner", "worker", or "judge" (nullable)
     * @param sessionId  groups all calls from the same agent session (nullable)
     * @param sessionTurn position in the conversation, e.g. 1, 2, 3 (nullable)
     */
    public SessionContext(String agentId, String agentRole, String sessionId, Integer sessionTurn) {
        this.agentId = agentId;
        this.agentRole = agentRole;
        this.sessionId = sessionId;
        this.sessionTurn = sessionTurn;
    }

    /** Get the agent identifier. */
    public String getAgentId() { return agentId; }

    /** Get the agent role. */
    public String getAgentRole() { return agentRole; }

    /** Get the session identifier. */
    public String getSessionId() { return sessionId; }

    /** Get the session turn number. */
    public Integer getSessionTurn() { return sessionTurn; }

    /**
     * The wire fields for the governance request body, in a fixed order.
     * Only fields that are set appear: null (or, for the string fields, empty)
     * values are omitted. {@code session_turn} is an integer.
     *
     * @return an unmodifiable map; empty when nothing is set
     */
    public Map<String, Object> toRequestFields() {
        Map<String, Object> fields = new LinkedHashMap<>();
        if (agentId != null && !agentId.isEmpty()) fields.put("agent_id", agentId);
        if (agentRole != null && !agentRole.isEmpty()) fields.put("agent_role", agentRole);
        if (sessionId != null && !sessionId.isEmpty()) fields.put("session_id", sessionId);
        if (sessionTurn != null) fields.put("session_turn", sessionTurn);
        return Collections.unmodifiableMap(fields);
    }

    @Override
    public String toString() {
        return "SessionContext{" +
                "agentId='" + agentId + '\'' +
                ", agentRole='" + agentRole + '\'' +
                ", sessionId='" + sessionId + '\'' +
                ", sessionTurn=" + sessionTurn +
                '}';
    }
}
