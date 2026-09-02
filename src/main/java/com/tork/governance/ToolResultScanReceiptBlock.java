package com.tork.governance;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * The {@code tool_result_scan} block recorded on a receipt. Mirrors
 * {@code ToolResultScanReceiptBlock} in tork-js-sdk/src/tool-result-scan.ts
 * and Go's {@code ToolResultScanReceiptBlock} in tork-go-sdk/toolresultscan.go.
 *
 * <p><b>Byte-identical contract (DECIDED-TACT2-V2-C):</b> {@link #toJson()}
 * emits snake_case keys in alphabetical order, and OMITS {@code reason} and
 * {@code server_uri} entirely when absent rather than emitting them as
 * {@code null} -- the same discipline as the JS SDK's TORK-DNA-v2 canonical
 * form. Every SDK mirroring this must produce a byte-identical block for the
 * same scan. Key order:
 * {@code attested_by, blocked, capture_mode, findings, injection_ruleset,
 * [reason], sdk_language, sdk_version, [server_uri], tool_name, totals}.</p>
 *
 * <p>It carries COUNTS ONLY. No payload, no matched substring, no location
 * path, no tool argument ever appears here.</p>
 */
public final class ToolResultScanReceiptBlock {

    /** Always "client". This scan ran in the caller's process; Tork did not execute it. */
    private final String attestedBy = "client";
    private final boolean blocked;
    /** Always "edge" -- the capture_mode this SDK's client-side work is recorded under. */
    private final String captureMode = "edge";
    /** Counts by kind, then by type, each sorted alphabetically by type key. */
    private final Map<String, Integer> injectionFindings;
    private final Map<String, Integer> piiFindings;
    /** Identifier of the injection ruleset that produced the injection counts. */
    private final String injectionRuleset;
    /** Present only when blocked. Nullable. */
    private final String reason;
    /** Always "java". */
    private final String sdkLanguage = "java";
    private final String sdkVersion;
    /** Present only when the caller supplied one. Nullable. */
    private final String serverUri;
    private final String toolName;
    private final int injectionTotal;
    private final int piiTotal;

    ToolResultScanReceiptBlock(boolean blocked, Map<String, Integer> injectionFindings,
                                Map<String, Integer> piiFindings, String injectionRuleset,
                                String reason, String sdkVersion, String serverUri,
                                String toolName, int injectionTotal, int piiTotal) {
        this.blocked = blocked;
        this.injectionFindings = new TreeMap<>(injectionFindings);
        this.piiFindings = new TreeMap<>(piiFindings);
        this.injectionRuleset = injectionRuleset;
        this.reason = reason;
        this.sdkVersion = sdkVersion;
        this.serverUri = serverUri;
        this.toolName = toolName;
        this.injectionTotal = injectionTotal;
        this.piiTotal = piiTotal;
    }

    public String getAttestedBy() {
        return attestedBy;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public String getCaptureMode() {
        return captureMode;
    }

    public Map<String, Integer> getInjectionFindings() {
        return injectionFindings;
    }

    public Map<String, Integer> getPiiFindings() {
        return piiFindings;
    }

    public String getInjectionRuleset() {
        return injectionRuleset;
    }

    public String getReason() {
        return reason;
    }

    public String getSdkLanguage() {
        return sdkLanguage;
    }

    public String getSdkVersion() {
        return sdkVersion;
    }

    public String getServerUri() {
        return serverUri;
    }

    public String getToolName() {
        return toolName;
    }

    public int getInjectionTotal() {
        return injectionTotal;
    }

    public int getPiiTotal() {
        return piiTotal;
    }

    /**
     * An ordered map view of this block: snake_case keys in the same
     * alphabetical order {@link #toJson()} emits, with {@code reason} and
     * {@code server_uri} omitted entirely when absent.
     */
    public Map<String, Object> toOrderedMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("attested_by", attestedBy);
        map.put("blocked", blocked);
        map.put("capture_mode", captureMode);
        Map<String, Object> findings = new LinkedHashMap<>();
        findings.put("injection", injectionFindings);
        findings.put("pii", piiFindings);
        map.put("findings", findings);
        map.put("injection_ruleset", injectionRuleset);
        if (reason != null) {
            map.put("reason", reason);
        }
        map.put("sdk_language", sdkLanguage);
        map.put("sdk_version", sdkVersion);
        if (serverUri != null) {
            map.put("server_uri", serverUri);
        }
        map.put("tool_name", toolName);
        Map<String, Object> totals = new LinkedHashMap<>();
        totals.put("injection", injectionTotal);
        totals.put("pii", piiTotal);
        map.put("totals", totals);
        return map;
    }

    /**
     * The canonical JSON form of this block: snake_case keys, alphabetical
     * order, {@code reason}/{@code server_uri} omitted (not nulled) when
     * absent. This is the byte-identical cross-SDK artifact.
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"attested_by\":\"").append(attestedBy).append('"').append(',');
        sb.append("\"blocked\":").append(blocked).append(',');
        sb.append("\"capture_mode\":\"").append(captureMode).append('"').append(',');
        sb.append("\"findings\":{");
        sb.append("\"injection\":");
        appendCounts(sb, injectionFindings);
        sb.append(',');
        sb.append("\"pii\":");
        appendCounts(sb, piiFindings);
        sb.append('}').append(',');
        sb.append("\"injection_ruleset\":\"").append(jsonEscape(injectionRuleset)).append('"').append(',');
        if (reason != null) {
            sb.append("\"reason\":\"").append(jsonEscape(reason)).append('"').append(',');
        }
        sb.append("\"sdk_language\":\"").append(sdkLanguage).append('"').append(',');
        sb.append("\"sdk_version\":\"").append(jsonEscape(sdkVersion)).append('"').append(',');
        if (serverUri != null) {
            sb.append("\"server_uri\":\"").append(jsonEscape(serverUri)).append('"').append(',');
        }
        sb.append("\"tool_name\":\"").append(jsonEscape(toolName)).append('"').append(',');
        sb.append("\"totals\":{\"injection\":").append(injectionTotal)
            .append(",\"pii\":").append(piiTotal).append('}');
        sb.append('}');
        return sb.toString();
    }

    private static void appendCounts(StringBuilder sb, Map<String, Integer> counts) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(jsonEscape(entry.getKey())).append("\":").append(entry.getValue());
        }
        sb.append('}');
    }

    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    @Override
    public String toString() {
        return toJson();
    }
}
