package com.tork.governance;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tool-result scanning (DECIDED-TACT2-V2-C), ported from
 * tork-js-sdk/src/tool-result-scan.ts (see also the Go port,
 * tork-go-sdk/toolresultscan.go + injection.go).
 *
 * <p>A tool result returned by an MCP server -- or by any external system
 * the caller does not control -- is untrusted input that is about to be
 * appended to a model's context. {@link #scanToolResult} scans it BEFORE
 * that happens, on-device, for two things:</p>
 *
 * <ol>
 *   <li>PII, using the SAME on-device detector as {@link Tork#govern}
 *   ({@link PIIDetector}). Nothing new was written for this: same patterns,
 *   same redaction labels, same zero-network guarantee. This class does not
 *   duplicate a single regex from {@link PIIDetector} -- it calls it.</li>
 *   <li>Prompt injection, using the conservative heuristic pattern set
 *   below. Every injection finding is labelled {@code heuristic:<type>} so
 *   no caller can mistake a regex hit for a verified determination.</li>
 * </ol>
 *
 * <p><b>ZERO NETWORK.</b> Every method here is pure and synchronous: no
 * socket, no file I/O, no clock read. The payload never leaves the
 * machine.</p>
 *
 * <p><b>WHAT THIS IS NOT:</b> this is a client-side control that the CALLER
 * runs and the caller attests to. It is not gateway-side enforcement -- a
 * compromised or simply careless caller can skip it entirely, and Tork
 * cannot tell. Enforcement at the gateway, where skipping is not an option,
 * is a separate and later control.</p>
 *
 * <p><b>PARITY TIER:</b> this port matches Tier 1 of the JS SDK -- the
 * 10-type basic PII vocabulary ({@code ssn, credit_card, email, phone,
 * address, ip_address, date_of_birth, passport, drivers_license,
 * bank_account}) with JS-identical labels and redaction markers. It does
 * NOT carry the Python SDK's regional/industry pattern tier
 * (AU/US/GB/EU/AE/... profiles) -- this SDK's regional detection (see
 * {@code Tork#govern(String, List, String)}) is a separate, older mechanism
 * and is not wired into {@code scanToolResult}.</p>
 *
 * <h2>Engine differences from the JS source (documented workarounds)</h2>
 * <ul>
 *   <li>JS regex literals are slash-delimited, so {@code https:\/\/} escapes
 *   the slash; Java regex strings have no such delimiter, so the escaping
 *   is dropped ({@code https://}) -- a syntax adaptation only, never a
 *   semantic change.</li>
 *   <li>JS's {@code /gi} and {@code /gim} flags become
 *   {@link Pattern#CASE_INSENSITIVE} and {@link Pattern#MULTILINE} passed to
 *   {@link Pattern#compile(String, int)}; "global" match-all is just how
 *   {@link Matcher#find()} in a loop already behaves.</li>
 *   <li>JS's comment on {@code tool-result-scan.ts} notes it must build "a
 *   fresh regex per call" because a {@code /g} {@code RegExp} literal is
 *   stateful ({@code lastIndex} persists across calls, unsafe to share).
 *   Java's {@link Pattern} is immutable and thread-safe; {@link Matcher}
 *   instances created via {@link Pattern#matcher} are independent per call,
 *   so the injection patterns below are compiled ONCE as static finals with
 *   no equivalent workaround needed.</li>
 *   <li>Java {@link Map} implementations (other than
 *   {@link LinkedHashMap}) do not guarantee iteration order the way a JS
 *   object preserves key-insertion order, so {@link #walk} sorts a map's
 *   keys before traversing (same reasoning as the Go port's map-key
 *   sort, which compensates for Go's randomized map iteration order).</li>
 * </ul>
 */
public final class ToolResultScanner {

    private ToolResultScanner() {
    }

    // ========================================================================
    // Injection heuristics
    // ========================================================================

    /**
     * Prefix on every injection finding's type. Not cosmetic: these
     * patterns are regexes over untrusted text, they carry false positives
     * and false negatives, and the label travels with the finding into the
     * receipt.
     */
    public static final String INJECTION_HEURISTIC_PREFIX = "heuristic:";

    /**
     * Identifies this exact pattern set in receipts. Bump when the patterns
     * change, so a receipt says which ruleset produced its counts. Every
     * SDK mirroring this implementation must emit the SAME value for the
     * same ruleset -- it is a shared identifier, not a per-language one.
     */
    public static final String INJECTION_RULESET = "tork-injection-heuristics-v1";

    private static final class InjectionPattern {
        final String type;
        final Pattern pattern;

        InjectionPattern(String type, Pattern pattern) {
            this.type = type;
            this.pattern = pattern;
        }
    }

    /**
     * Conservative on purpose. Each pattern targets a phrase that has no
     * plausible reason to appear in a legitimate tool result -- a database
     * row, a search hit, a file listing. Broader "suspicious language"
     * matching would fire on ordinary documentation and support tickets,
     * and an alert nobody believes is worse than no alert.
     *
     * <p>Regex SOURCE STRINGS below are ported verbatim from
     * tork-js-sdk/src/tool-result-scan.ts's {@code INJECTION_PATTERNS},
     * modulo the syntax adaptations documented in the class Javadoc.</p>
     */
    private static final List<InjectionPattern> INJECTION_PATTERNS = Collections.unmodifiableList(new ArrayList<InjectionPattern>() {{
        // -- instruction override --------------------------------------------
        add(new InjectionPattern("instruction_override", Pattern.compile(
            "\\b(?:ignore|disregard|forget|override|bypass)\\b[^.\\n]{0,40}\\b(?:previous|prior|earlier|above|preceding|all|any)\\b[^.\\n]{0,30}\\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\\b",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("instruction_override", Pattern.compile(
            "\\b(?:the\\s+)?(?:instructions?|prompts?|rules?)\\s+(?:above|below|before\\s+this)\\s+(?:are|is)\\s+(?:now\\s+)?(?:void|invalid|obsolete|outdated|no\\s+longer\\s+(?:valid|active|in\\s+effect))\\b",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("instruction_override", Pattern.compile(
            "\\bdisregard\\s+(?:your|the)\\s+(?:system\\s+)?(?:prompt|instructions?|guidelines?)\\b",
            Pattern.CASE_INSENSITIVE)));

        // -- role reassignment ------------------------------------------------
        add(new InjectionPattern("role_reassignment", Pattern.compile(
            "\\byou\\s+are\\s+(?:now|no\\s+longer)\\s+(?:a|an|the)\\b",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("role_reassignment", Pattern.compile(
            "\\b(?:from\\s+now\\s+on|starting\\s+now|for\\s+the\\s+rest\\s+of\\s+this\\s+(?:conversation|session))\\b[^.\\n]{0,30}\\byou\\s+(?:are|will|must|should)\\b",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("role_reassignment", Pattern.compile(
            "\\bnew\\s+(?:system\\s+)?(?:instructions?|prompt|persona|role)\\s*:",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("role_reassignment", Pattern.compile(
            "\\b(?:enable|enter|activate|switch\\s+to)\\s+(?:developer|god|dan|jailbreak|unrestricted)\\s+mode\\b",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("role_reassignment", Pattern.compile(
            "\\b(?:act|behave|respond|pretend\\s+to\\s+be)\\s+as\\s+(?:if\\s+you\\s+(?:are|were)\\s+)?(?:an?\\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\\b",
            Pattern.CASE_INSENSITIVE)));
        // A role header smuggled into content -- "system:" / "<|im_start|>system"
        // at the start of a line is a conversation-structure forgery, not prose.
        add(new InjectionPattern("role_reassignment", Pattern.compile(
            "^[ \\t>*-]*(?:<\\|im_start\\|>\\s*)?(?:system|assistant|developer)\\s*(?::|\\]|>)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE)));

        // -- exfiltration -----------------------------------------------------
        // A markdown image/link whose URL carries the content out as a query
        // parameter -- the classic zero-click exfiltration shape.
        add(new InjectionPattern("exfiltration_url", Pattern.compile(
            "!?\\[[^\\]\\n]*\\]\\(\\s*https?://[^)\\s]*[?&][^)\\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\\s]*\\)",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("exfiltration_url", Pattern.compile(
            "\\bhttps?://\\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=",
            Pattern.CASE_INSENSITIVE)));
        add(new InjectionPattern("exfiltration_url", Pattern.compile(
            "\\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\\b[^.\\n]{0,60}\\bto\\s+https?://\\S+",
            Pattern.CASE_INSENSITIVE)));
    }});

    /** Distinct injection types the ruleset can emit, for documentation/tests. */
    public static final List<String> INJECTION_TYPES;

    static {
        Set<String> types = new TreeSet<>();
        for (InjectionPattern p : INJECTION_PATTERNS) {
            types.add(p.type);
        }
        INJECTION_TYPES = Collections.unmodifiableList(new ArrayList<>(types));
    }

    // ========================================================================
    // Traversal
    // ========================================================================

    private static final int DEFAULT_MAX_DEPTH = 32;

    private static final Pattern IDENTIFIER = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*$");

    private static String childPath(String parent, String key) {
        if (IDENTIFIER.matcher(key).matches()) {
            return parent + "." + key;
        }
        return parent + "[" + jsonQuote(key) + "]";
    }

    private static String jsonQuote(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2);
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                default:
                    out.append(c);
            }
        }
        out.append('"');
        return out.toString();
    }

    /**
     * Scan one string: PII (via the shared {@link PIIDetector}) then
     * injection heuristics. Returns the masked string; findings are
     * appended in place, keyed to {@code location}.
     */
    private static String scanString(String text, String location, Map<String, Pattern> customPatterns,
                                      List<ToolResultFinding> findings) {
        PIIDetector.DetectionResult pii = new PIIDetector().detectAndRedact(text);

        if (pii.getCount() > 0) {
            // Counts per type, emitted in a stable (sorted-by-code) order so
            // two runs over the same payload produce identical findings.
            Map<String, Integer> perType = new TreeMap<>();
            for (PIIDetector.PIIMatch match : pii.getMatches()) {
                String code = match.getType().getCode();
                perType.merge(code, 1, Integer::sum);
            }
            for (Map.Entry<String, Integer> entry : perType.entrySet()) {
                findings.add(new ToolResultFinding(ToolResultFindingKind.PII, entry.getKey(), entry.getValue(), location));
            }
        }

        Map<String, Integer> perInjectionType = new TreeMap<>();
        for (InjectionPattern ip : INJECTION_PATTERNS) {
            Matcher m = ip.pattern.matcher(text);
            int count = 0;
            while (m.find()) {
                count++;
            }
            if (count > 0) {
                perInjectionType.merge(ip.type, count, Integer::sum);
            }
        }
        for (Map.Entry<String, Integer> entry : perInjectionType.entrySet()) {
            findings.add(new ToolResultFinding(
                ToolResultFindingKind.INJECTION, INJECTION_HEURISTIC_PREFIX + entry.getKey(), entry.getValue(), location));
        }

        String redacted = pii.getRedactedText();

        // Extra caller-supplied patterns, applied AFTER default detection
        // and redaction, for redaction only -- they never produce a
        // finding, matching the JS/Go SDKs' documented behavior. Applied in
        // sorted-name order for determinism.
        if (customPatterns != null && !customPatterns.isEmpty()) {
            List<String> names = new ArrayList<>(customPatterns.keySet());
            Collections.sort(names);
            for (String name : names) {
                Pattern p = customPatterns.get(name);
                String replacement = Matcher.quoteReplacement("[" + name.toUpperCase(Locale.ROOT) + "_REDACTED]");
                redacted = p.matcher(redacted).replaceAll(replacement);
            }
        }

        return redacted;
    }

    /**
     * Walk the payload, scanning every string. Returns a structure with PII
     * masked in place; sub-trees with nothing to mask keep their original
     * identity, so an untouched payload's containers come back as the same
     * {@link Map}/{@link List}/array instances that were passed in.
     *
     * <p>Only strings are scanned. Numbers, booleans, and anything that is
     * not a {@link String}, {@link Map}, {@link List}, or array passes
     * through untouched -- a bank account stored as a boxed number is NOT
     * detected. Cycles (self-referential maps/lists) are left as-is and not
     * re-entered, guarded by object identity (an {@link IdentityHashMap}
     * used as a set, matching the JS source's {@code WeakSet}).</p>
     */
    private static Object walk(Object value, String location, int depth, int maxDepth,
                                Map<String, Pattern> customPatterns, List<ToolResultFinding> findings,
                                Map<Object, Boolean> seen) {
        if (value instanceof String) {
            return scanString((String) value, location, customPatterns, findings);
        }

        if (depth >= maxDepth || value == null) {
            return value;
        }

        if (value instanceof Map) {
            if (seen.containsKey(value)) {
                return value;
            }
            seen.put(value, Boolean.TRUE);

            Map<?, ?> map = (Map<?, ?>) value;
            // Java Map implementations (other than LinkedHashMap) don't
            // guarantee iteration order the way a JS object preserves
            // key-insertion order, so keys are sorted for determinism.
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);

            Map<String, Object> byKey = new LinkedHashMap<>();
            for (Object k : map.keySet()) {
                byKey.put(String.valueOf(k), map.get(k));
            }

            boolean changed = false;
            Map<String, Object> out = new LinkedHashMap<>();
            for (String key : keys) {
                Object item = byKey.get(key);
                Object next = walk(item, childPath(location, key), depth + 1, maxDepth, customPatterns, findings, seen);
                if (next != item) {
                    changed = true;
                }
                out.put(key, next);
            }
            return changed ? out : value;
        }

        if (value instanceof List) {
            if (seen.containsKey(value)) {
                return value;
            }
            seen.put(value, Boolean.TRUE);

            List<?> list = (List<?>) value;
            boolean changed = false;
            List<Object> out = new ArrayList<>(list.size());
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                Object next = walk(item, location + "[" + i + "]", depth + 1, maxDepth, customPatterns, findings, seen);
                if (next != item) {
                    changed = true;
                }
                out.add(next);
            }
            return changed ? out : value;
        }

        if (value.getClass().isArray() && !value.getClass().getComponentType().isPrimitive()) {
            if (seen.containsKey(value)) {
                return value;
            }
            seen.put(value, Boolean.TRUE);

            Object[] arr = (Object[]) value;
            boolean changed = false;
            Object[] out = new Object[arr.length];
            for (int i = 0; i < arr.length; i++) {
                Object item = arr[i];
                Object next = walk(item, location + "[" + i + "]", depth + 1, maxDepth, customPatterns, findings, seen);
                if (next != item) {
                    changed = true;
                }
                out[i] = next;
            }
            return changed ? out : value;
        }

        return value;
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /**
     * Scan a tool result for PII and prompt injection before it is appended
     * to model context. Pure, synchronous, on-device: makes no network call
     * and mutates nothing reachable from {@code input.getPayload()}.
     *
     * <p>For the receipt-linked form ({@code attested_by='client'},
     * {@code capture_mode='edge'}), use {@link Tork#scanToolResult}, which
     * wraps this and records the scan.</p>
     */
    public static ToolResultScanResult scanToolResult(ToolResultScanInput input, ToolResultScanOptions options) {
        ToolResultScanOptions opts = options != null ? options : new ToolResultScanOptions();
        int maxDepth = opts.getMaxDepth() != null ? opts.getMaxDepth() : DEFAULT_MAX_DEPTH;

        List<ToolResultFinding> findings = new ArrayList<>();
        Object sanitized = walk(
            input.getPayload(), "$", 0, maxDepth, opts.getCustomPatterns(), findings, new IdentityHashMap<>());

        int injectionCount = scanInjectionCount(findings);
        boolean blocked = opts.isBlockOnInjection() && injectionCount > 0;

        if (blocked) {
            Set<String> typeSet = new TreeSet<>();
            for (ToolResultFinding f : findings) {
                if (f.getKind() == ToolResultFindingKind.INJECTION) {
                    typeSet.add(f.getType());
                }
            }
            String reason = "Blocked: " + injectionCount + " prompt-injection heuristic match(es) ["
                + String.join(", ", typeSet) + "] in the result of tool \"" + input.getToolName() + "\". "
                + "These are heuristic pattern matches (" + INJECTION_RULESET + "), not a verified determination. "
                + "sanitized is null so no masked copy can be appended to context by accident.";
            return new ToolResultScanResult(null, findings, true, reason);
        }

        return new ToolResultScanResult(sanitized, findings, false, null);
    }

    // ========================================================================
    // Receipt block
    // ========================================================================

    private static Map<String, Integer> countsByType(List<ToolResultFinding> findings, ToolResultFindingKind kind) {
        Map<String, Integer> totals = new TreeMap<>();
        for (ToolResultFinding f : findings) {
            if (f.getKind() != kind) {
                continue;
            }
            totals.merge(f.getType(), f.getCount(), Integer::sum);
        }
        return totals;
    }

    private static int sumCounts(Map<String, Integer> counts) {
        int sum = 0;
        for (int v : counts.values()) {
            sum += v;
        }
        return sum;
    }

    /**
     * Build the receipt block for a completed scan.
     *
     * @param toolName   name of the tool that produced the scanned result
     * @param serverUri  URI of the MCP server (or other origin); nullable
     * @param result     the completed scan result
     * @param sdkVersion this SDK's version, as reported on the block
     */
    public static ToolResultScanReceiptBlock buildToolResultScanBlock(
        String toolName, String serverUri, ToolResultScanResult result, String sdkVersion) {
        Map<String, Integer> pii = countsByType(result.getFindings(), ToolResultFindingKind.PII);
        Map<String, Integer> injection = countsByType(result.getFindings(), ToolResultFindingKind.INJECTION);

        return new ToolResultScanReceiptBlock(
            result.isBlocked(), injection, pii, INJECTION_RULESET, result.getReason(), sdkVersion,
            serverUri, toolName, sumCounts(injection), sumCounts(pii));
    }

    /** Distinct PII types in a scan result, for the attestation canonical form. */
    public static List<String> scanPIITypes(List<ToolResultFinding> findings) {
        Set<String> types = new TreeSet<>();
        for (ToolResultFinding f : findings) {
            if (f.getKind() == ToolResultFindingKind.PII) {
                types.add(f.getType());
            }
        }
        return new ArrayList<>(types);
    }

    /** Total PII match count in a scan result. */
    public static int scanPIICount(List<ToolResultFinding> findings) {
        int n = 0;
        for (ToolResultFinding f : findings) {
            if (f.getKind() == ToolResultFindingKind.PII) {
                n += f.getCount();
            }
        }
        return n;
    }

    /** Total injection match count in a scan result. */
    public static int scanInjectionCount(List<ToolResultFinding> findings) {
        int n = 0;
        for (ToolResultFinding f : findings) {
            if (f.getKind() == ToolResultFindingKind.INJECTION) {
                n += f.getCount();
            }
        }
        return n;
    }

    // ========================================================================
    // Hashing support (Java-specific; see Tork#scanToolResult)
    // ========================================================================

    /**
     * A deterministic, JSON-like text rendering of an arbitrary JSON-shaped
     * value, used only to compute {@code Receipt#getInputHash}/{@code
     * getOutputHash} for {@link Tork#scanToolResult}. Map keys are sorted so
     * the same logical value hashes the same way regardless of the source
     * map's iteration order (matching the {@link #walk} traversal's own
     * key-sort discipline).
     *
     * <p>NOTE: this is a Java-specific choice, not part of the
     * byte-identical {@code tool_result_scan} block contract -- only
     * {@link ToolResultScanReceiptBlock#toJson()} is specified to match
     * across SDKs. This function exists solely so the wrapping receipt's
     * hashes are deterministic and non-reversible, the same property the
     * JS/Go SDKs' equivalent hashing has, without claiming byte-for-byte
     * agreement with either.</p>
     */
    static String stableStringify(Object value) {
        StringBuilder sb = new StringBuilder();
        stableStringify(value, sb);
        return sb.toString();
    }

    private static void stableStringify(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            sb.append(jsonQuote((String) value));
        } else if (value instanceof Boolean || value instanceof Number) {
            sb.append(value);
        } else if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);
            Map<String, Object> byKey = new LinkedHashMap<>();
            for (Object k : map.keySet()) {
                byKey.put(String.valueOf(k), map.get(k));
            }
            sb.append('{');
            boolean first = true;
            for (String key : keys) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append(jsonQuote(key)).append(':');
                stableStringify(byKey.get(key), sb);
            }
            sb.append('}');
        } else if (value instanceof List) {
            List<?> list = (List<?>) value;
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                stableStringify(list.get(i), sb);
            }
            sb.append(']');
        } else if (value.getClass().isArray() && !value.getClass().getComponentType().isPrimitive()) {
            Object[] arr = (Object[]) value;
            sb.append('[');
            for (int i = 0; i < arr.length; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                stableStringify(arr[i], sb);
            }
            sb.append(']');
        } else {
            sb.append(jsonQuote(String.valueOf(value)));
        }
    }
}
