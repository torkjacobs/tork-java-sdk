package com.tork.governance;

/**
 * Agent/session context for multi-agent governance tracking.
 *
 * <p>All fields are optional. When provided, they are included in the POST body
 * to /api/v1/govern and returned in the receipt under {@code session_context}.</p>
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
