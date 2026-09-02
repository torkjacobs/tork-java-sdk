package com.tork.governance;

import java.util.Objects;

/**
 * One (kind, type, location) match tally, produced while scanning a tool
 * result. Mirrors {@code ToolResultFinding} in
 * tork-js-sdk/src/tool-result-scan.ts.
 */
public final class ToolResultFinding {

    private final ToolResultFindingKind kind;
    /**
     * For kind PII, a {@link PIIType} code ("ssn", "email", ...). For kind
     * INJECTION, always {@code heuristic:<name>} -- the prefix is part of
     * the value, not decoration, so a downstream reader of a receipt cannot
     * mistake a pattern hit for a verified determination.
     */
    private final String type;
    /** Number of matches of this (kind, type) at this location. */
    private final int count;
    /** JSON path of the string the matches were found in, e.g. {@code $.content[0].text}. */
    private final String location;

    public ToolResultFinding(ToolResultFindingKind kind, String type, int count, String location) {
        this.kind = kind;
        this.type = type;
        this.count = count;
        this.location = location;
    }

    public ToolResultFindingKind getKind() {
        return kind;
    }

    public String getType() {
        return type;
    }

    public int getCount() {
        return count;
    }

    public String getLocation() {
        return location;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ToolResultFinding)) return false;
        ToolResultFinding that = (ToolResultFinding) o;
        return count == that.count
            && kind == that.kind
            && Objects.equals(type, that.type)
            && Objects.equals(location, that.location);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, type, count, location);
    }

    @Override
    public String toString() {
        return "ToolResultFinding{kind=" + kind + ", type='" + type + "', count=" + count
            + ", location='" + location + "'}";
    }
}
