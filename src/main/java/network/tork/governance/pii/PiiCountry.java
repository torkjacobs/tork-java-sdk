package network.tork.governance.pii;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;

/**
 * The country layer: 24 country profiles, 51 patterns, 20 check digits.
 *
 * <p>This implements the seven rules that {@code generated/sdk-registry/README.md}
 * marks <b>SDK</b>, from the bundle alone. Bundle 1.1.0 carries the data all
 * seven need -- the activation signals, the country map, the three windows, the
 * whole-word vocabulary, the near-miss policy, the table constants and the
 * reference labels -- so nothing here is hand-written registry data and no
 * window is hard-coded.
 *
 * <ol>
 *   <li>ACTIVATE -- a country's patterns run only when one of its signals fires.</li>
 *   <li>MATCH -- the regex, case-sensitively, globally.</li>
 *   <li>KEYWORD -- whole-word (symmetric CONTEXT_WINDOW) or column verdict or the
 *       ASYMMETRIC substring window (60 before, 40 after); then 7b may close it.</li>
 *   <li>CHECKSUM -- when required. Advisory checksums never reject.</li>
 *   <li>SUPERSEDE -- a match containing every range it overlaps takes them.</li>
 *   <li>NEAR MISS -- a checksum-failing identifier is redacted generically.</li>
 *   <li>COLUMN -- in a delimited table a bare value cell is judged by its header.</li>
 *   <li>7b NEAREST LABEL -- a closer commercial label closes the gate.</li>
 * </ol>
 *
 * <p>Still cloud-only, by design: the universal (L0) patterns, the slot, context,
 * gravity and name layers, industry profiles and org configuration.
 *
 * <p>Targets Java 11: no records, no {@code var} in fields, no text blocks.
 */
public final class PiiCountry {

    /** Characters before a match that count as nearby for the substring gate. */
    public static final int KEYWORD_WINDOW_BEFORE = PiiRegistry.KEYWORD_WINDOW_BEFORE;
    /** Characters after. Deliberately NOT the same number as before. */
    public static final int KEYWORD_WINDOW_AFTER = PiiRegistry.KEYWORD_WINDOW_AFTER;
    /** The symmetric window: whole-word keywords and the near-miss gate. */
    public static final int CONTEXT_WINDOW = PiiRegistry.CONTEXT_WINDOW;
    /** The bundle this SDK shipped. */
    public static final String REGISTRY_VERSION = PiiRegistry.VERSION;
    /** The bundle content hash, which answers "did the data change". */
    public static final String CONTENT_HASH = PiiRegistry.CONTENT_HASH;

    private PiiCountry() {}

    /** One country identifier found in the content. */
    public static final class CountryMatch {
        public final String name;
        public final String country;
        public final String label;
        public final String type;
        public final String redaction;
        public final int startIndex;
        public final int endIndex;

        public CountryMatch(String name, String country, String label, String type,
                            String redaction, int startIndex, int endIndex) {
            this.name = name;
            this.country = country;
            this.label = label;
            this.type = type;
            this.redaction = redaction;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        public String name() { return name; }
        public String country() { return country; }
        public String label() { return label; }
        public String type() { return type; }
        public String redaction() { return redaction; }
        public int startIndex() { return startIndex; }
        public int endIndex() { return endIndex; }

        // JavaBean accessors, for the callers written against them.
        public String getName() { return name; }
        public String getCountry() { return country; }
        public String getLabel() { return label; }
        public String getType() { return type; }
        public String getRedaction() { return redaction; }
        public int getStartIndex() { return startIndex; }
        public int getEndIndex() { return endIndex; }
    }

    /** A span of the original text and the token that replaces it. */
    public static final class RedactionSpan {
        public final int startIndex;
        public final int endIndex;
        public final String redaction;

        public RedactionSpan(int startIndex, int endIndex, String redaction) {
            this.startIndex = startIndex;
            this.endIndex = endIndex;
            this.redaction = redaction;
        }

        public int getStartIndex() { return startIndex; }
        public int getEndIndex() { return endIndex; }
        public String getRedaction() { return redaction; }
    }

    /** Matches, plus the caller's own L0 ranges that rule 5 superseded. */
    public static final class Result {
        public final List<CountryMatch> matches;
        public final List<int[]> supersededRanges;

        Result(List<CountryMatch> matches, List<int[]> supersededRanges) {
            this.matches = matches;
            this.supersededRanges = supersededRanges;
        }
    }

    // ── compiled once, in a static block ────────────────────────────────────

    private static final Map<String, java.util.regex.Pattern> COMPILED = new HashMap<>();
    private static final Map<String, PiiRegistry.Pattern> BY_NAME = new HashMap<>();
    private static final List<java.util.regex.Pattern> COMPILED_SIGNALS = new ArrayList<>();
    private static final List<String> SIGNAL_ORDER = new ArrayList<>();
    private static final Map<String, List<String>> COUNTRY_PATTERNS = new LinkedHashMap<>();
    private static final Set<String> GENERIC_SET;
    private static final List<String> NATIONAL_ID_KEYWORDS = new ArrayList<>();

    static {
        for (PiiRegistry.Pattern p : PiiRegistry.PATTERNS) {
            COMPILED.put(p.name, java.util.regex.Pattern.compile(p.regex));
            BY_NAME.put(p.name, p);
        }
        for (PiiRegistry.Signal s : PiiRegistry.SIGNALS) {
            int flags = s.flags.contains("i") ? java.util.regex.Pattern.CASE_INSENSITIVE : 0;
            COMPILED_SIGNALS.add(java.util.regex.Pattern.compile(s.regex, flags));
            if (!SIGNAL_ORDER.contains(s.country)) SIGNAL_ORDER.add(s.country);
        }
        for (PiiRegistry.Country c : PiiRegistry.COUNTRIES) COUNTRY_PATTERNS.put(c.code, c.patterns);
        GENERIC_SET = new HashSet<>(PiiRegistry.GENERIC_ID_KEYWORDS);
        NATIONAL_ID_KEYWORDS.addAll(PiiRegistry.GENERIC_ID_KEYWORDS);
        NATIONAL_ID_KEYWORDS.addAll(PiiRegistry.LOCAL_ID_KEYWORDS);
    }

    private static boolean isAlnum(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z');
    }

    /** A pattern's whole vocabulary: the substring keywords and the whole-word ones. */
    private static List<String> allKeywordsOf(PiiRegistry.Pattern p) {
        if (p.wholeWordKeywords.isEmpty()) return p.keywords;
        List<String> all = new ArrayList<>(p.keywords);
        all.addAll(p.wholeWordKeywords);
        return all;
    }

    /** The half of a vocabulary that names ONE country's identifier. */
    private static List<String> specificKeywords(List<String> keywords) {
        List<String> out = new ArrayList<>();
        for (String k : keywords) if (!GENERIC_SET.contains(k)) out.add(k);
        return out;
    }

    private static String window(String content, int lo, int hi) {
        int l = Math.max(0, lo);
        int h = Math.min(content.length(), hi);
        return h > l ? content.substring(l, h).toLowerCase() : "";
    }

    /** Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it. */
    private static boolean hasNearbyContext(String content, int start, int end, List<String> keywords) {
        String before = window(content, start - KEYWORD_WINDOW_BEFORE, start);
        String after = window(content, end, end + KEYWORD_WINDOW_AFTER);
        for (String kw : keywords) if (before.contains(kw) || after.contains(kw)) return true;
        return false;
    }

    /** Symmetric CONTEXT_WINDOW either side, substring. Used by rule 6. */
    private static boolean hasContextAround(String content, int start, int end, List<String> keywords) {
        String w = window(content, start - CONTEXT_WINDOW, end + CONTEXT_WINDOW);
        for (String kw : keywords) if (w.contains(kw)) return true;
        return false;
    }

    /**
     * Rule 3, whole-word half: symmetric CONTEXT_WINDOW, a boundary each side,
     * a boundary being "not a letter or digit".
     *
     * <p>This is the gate Indonesia needs: {@code nik} sits inside <i>teknik</i>,
     * <i>elektronik</i>, <i>klinik</i> and <i>pabrik</i>, so a substring test
     * would open the gate on a sales ledger.
     */
    public static boolean hasWholeWordContextAround(String content, int start, int end, List<String> words) {
        if (words == null || words.isEmpty()) return false;
        String w = window(content, start - CONTEXT_WINDOW, end + CONTEXT_WINDOW);
        for (String word : words) {
            int from = 0;
            while (from <= w.length() - word.length()) {
                int i = w.indexOf(word, from);
                if (i < 0) break;
                boolean beforeOk = i == 0 || !isAlnum(w.charAt(i - 1));
                int j = i + word.length();
                boolean afterOk = j >= w.length() || !isAlnum(w.charAt(j));
                if (beforeOk && afterOk) return true;
                from = i + 1;
            }
        }
        return false;
    }

    private static boolean documentHasWholeWord(String content, List<String> words) {
        return words != null && !words.isEmpty()
            && hasWholeWordContextAround(content, 0, content.length(), words);
    }

    // ── rule 1: activation ──────────────────────────────────────────────────

    /** The countries this text activates, in the bundle's signal order. */
    public static List<String> inferRegions(String content) {
        List<String> regions = new ArrayList<>();
        String lower = content.toLowerCase();
        for (String code : SIGNAL_ORDER) {
            for (int i = 0; i < PiiRegistry.SIGNALS.size(); i++) {
                PiiRegistry.Signal s = PiiRegistry.SIGNALS.get(i);
                if (!s.country.equals(code)) continue;
                if (!COMPILED_SIGNALS.get(i).matcher(content).find()) continue;

                boolean bySubstring = false;
                for (String k : s.keywords) {
                    if (lower.contains(k)) { bySubstring = true; break; }
                }
                boolean byWholeWord = documentHasWholeWord(content, s.wholeWordKeywords);
                // Both lists empty means the shape alone is distinctive enough.
                if ((!s.keywords.isEmpty() || !s.wholeWordKeywords.isEmpty())
                    && !bySubstring && !byWholeWord) {
                    continue;
                }
                String target = s.activates.isEmpty() ? code : s.activates;
                if (!regions.contains(target)) regions.add(target);
                break; // one signal per country is enough
            }
        }
        return regions;
    }

    /**
     * Rule 1a: the patterns that run on every document, whatever rule 1
     * returned, and before the activated country patterns so an activated
     * pattern can supersede one of these under rule 5.
     */
    public static List<PiiRegistry.Pattern> alwaysOnPatterns() {
        List<PiiRegistry.Pattern> out = new ArrayList<>();
        for (PiiRegistry.Pattern p : PiiRegistry.PATTERNS) if (p.alwaysOn()) out.add(p);
        return out;
    }

    /**
     * {@link #alwaysOnPatterns()} followed by the patterns rule 1's activated
     * regions switch on, de-duplicated, alwaysOn patterns first.
     */
    public static List<PiiRegistry.Pattern> patternsForContent(String content) {
        List<PiiRegistry.Pattern> out = new ArrayList<>(alwaysOnPatterns());
        Set<String> seen = new HashSet<>();
        for (PiiRegistry.Pattern p : out) seen.add(p.name);
        for (PiiRegistry.Pattern p : patternsForRegions(inferRegions(content))) {
            if (seen.add(p.name)) out.add(p);
        }
        return out;
    }

    /** The patterns those regions switch on, de-duplicated, in registry order. */
    public static List<PiiRegistry.Pattern> patternsForRegions(List<String> regions) {
        List<PiiRegistry.Pattern> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String code : regions) {
            List<String> names = COUNTRY_PATTERNS.get(code.toUpperCase());
            if (names == null) continue;
            for (String name : names) {
                if (!seen.add(name)) continue;
                PiiRegistry.Pattern p = BY_NAME.get(name);
                if (p != null) out.add(p);
            }
        }
        return out;
    }

    // ── rule 7: the column is the context ───────────────────────────────────

    private static final class TableScope {
        final int start, end, rowStart, rowEnd;
        final String header;

        TableScope(int start, int end, String header, int rowStart, int rowEnd) {
            this.start = start; this.end = end; this.header = header;
            this.rowStart = rowStart; this.rowEnd = rowEnd;
        }
    }

    private static final java.util.regex.Pattern HEADER_HAS_LETTER =
        java.util.regex.Pattern.compile("[A-Za-z\\u00C0-\\uFFFF]");
    private static final java.util.regex.Pattern HEADER_ALL_NUMERIC =
        java.util.regex.Pattern.compile("^\\+?[\\d\\s.\\-/]+$");
    private static final java.util.regex.Pattern HEADER_SENTENCE =
        java.util.regex.Pattern.compile("[.?!]");

    private static boolean looksLikeHeader(String[] cells, String delimiter) {
        int minimum = ",".equals(delimiter) ? PiiRegistry.TABLE_MIN_COMMA_COLUMNS : 2;
        if (cells.length < minimum) return false;
        for (String cell : cells) {
            String t = cell.trim();
            if (t.isEmpty() || t.length() > PiiRegistry.TABLE_MAX_HEADER_LENGTH) return false;
            if (!HEADER_HAS_LETTER.matcher(t).find()) return false;
            if (HEADER_ALL_NUMERIC.matcher(t).matches()) return false;
            if (HEADER_SENTENCE.matcher(t).find()) return false;
            if (t.split("\\s+").length > PiiRegistry.TABLE_MAX_HEADER_WORDS) return false;
        }
        return true;
    }

    /** True when the content parses as a delimited table with a header row. */
    public static boolean isTable(String content) {
        return !tableScopes(content).isEmpty();
    }

    private static List<TableScope> tableScopes(String content) {
        String[] lines = content.split("\n", -1);
        if (lines.length < PiiRegistry.TABLE_MIN_ROWS) return Collections.emptyList();

        int[] offsets = new int[lines.length];
        int at = 0;
        for (int i = 0; i < lines.length; i++) { offsets[i] = at; at += lines[i].length() + 1; }

        for (String delimiter : PiiRegistry.TABLE_DELIMITERS) {
            String[] headerCells = lines[0].split(java.util.regex.Pattern.quote(delimiter), -1);
            if (!looksLikeHeader(headerCells, delimiter)) continue;
            int width = headerCells.length;

            List<Integer> dataRows = new ArrayList<>();
            for (int i = 1; i < lines.length; i++) {
                if (lines[i].trim().isEmpty()) continue;
                if (lines[i].split(java.util.regex.Pattern.quote(delimiter), -1).length != width) {
                    return Collections.emptyList();
                }
                dataRows.add(i);
            }
            if (dataRows.size() < PiiRegistry.TABLE_MIN_ROWS - 1) continue;

            List<TableScope> scopes = new ArrayList<>();
            for (int row : dataRows) {
                String[] cells = lines[row].split(java.util.regex.Pattern.quote(delimiter), -1);
                int rowStart = offsets[row];
                int rowEnd = rowStart + lines[row].length();
                int cellStart = rowStart;
                for (int col = 0; col < width; col++) {
                    scopes.add(new TableScope(cellStart, cellStart + cells[col].length(),
                        headerCells[col].trim().toLowerCase(), rowStart, rowEnd));
                    cellStart += cells[col].length() + delimiter.length();
                }
            }
            return scopes;
        }
        return Collections.emptyList();
    }

    /** A whole-word match, not a substring. */
    private static boolean headerNames(String header, List<String> keywords) {
        for (String kw : keywords) {
            int i = header.indexOf(kw);
            if (i < 0) continue;
            boolean beforeOk = i == 0 || !isAlnum(header.charAt(i - 1));
            int j = i + kw.length();
            boolean afterOk = j >= header.length() || !isAlnum(header.charAt(j));
            if (beforeOk && afterOk) return true;
        }
        return false;
    }

    /** null when the window should be consulted as usual. */
    private static Boolean columnVerdict(String content, List<TableScope> scopes, int start, int end,
                                         List<String> all, List<String> specific) {
        if (scopes.isEmpty()) return null;
        TableScope cell = null;
        for (TableScope s : scopes) {
            if (start >= s.start && end <= s.end) { cell = s; break; }
        }
        if (cell == null) return null;
        // A cell whose own row names the identifier is prose in a delimited block.
        String rowText = window(content, cell.rowStart, cell.rowEnd);
        for (String k : all) if (rowText.contains(k)) return null;
        return !specific.isEmpty() && headerNames(cell.header, specific);
    }

    // ── rule 7b: nearest label wins ─────────────────────────────────────────

    private static Integer closestBefore(String before, List<String> keywords) {
        Integer best = null;
        for (String kw : keywords) {
            int i = before.lastIndexOf(kw);
            if (i < 0) continue;
            int d = before.length() - (i + kw.length());
            if (best == null || d < best) best = d;
        }
        return best;
    }

    private static Integer closestAfter(String after, List<String> keywords) {
        Integer best = null;
        for (String kw : keywords) {
            int i = after.indexOf(kw);
            if (i < 0) continue;
            if (best == null || i < best) best = i;
        }
        return best;
    }

    /**
     * Whether the number is labelled as a commercial reference more closely than
     * as an identifier. It can only ever close a gate, never open one.
     */
    public static boolean labelledAsReference(String content, int start, int end,
                                              List<String> identifierKeywords) {
        String before = window(content, start - PiiRegistry.LABEL_WINDOW, start);
        Integer reference = closestBefore(before, PiiRegistry.REFERENCE_LABELS);
        if (reference == null || reference > PiiRegistry.LABEL_REACH) return false;
        if (identifierKeywords == null || identifierKeywords.isEmpty()) return true;
        Integer idBefore = closestBefore(before, identifierKeywords);
        if (idBefore != null && idBefore <= reference) return false;
        String after = window(content, end, end + PiiRegistry.LABEL_WINDOW);
        Integer idAfter = closestAfter(after, identifierKeywords);
        if (idAfter != null && idAfter <= reference) return false;
        return true;
    }

    // ── the pass ────────────────────────────────────────────────────────────

    /** The span with leading and trailing non-alphanumeric characters removed. */
    public static int[] trimmedCore(String content, int start, int end) {
        int s = start, e = end;
        while (s < e && !isAlnum(content.charAt(s))) s++;
        while (e > s && !isAlnum(content.charAt(e - 1))) e--;
        return s == e ? new int[] {start, end} : new int[] {s, e};
    }

    /** Country matches for {@code content}, de-overlapped and ordered by position. */
    public static List<CountryMatch> detect(String content) {
        return detectWithRanges(content, null, null).matches;
    }

    /** Run an explicit pattern set, bypassing activation. */
    public static List<CountryMatch> detect(String content, List<PiiRegistry.Pattern> patterns) {
        return detectWithRanges(content, patterns, null).matches;
    }

    /** The full pass. Pass your own L0 spans so rule 5 can supersede them. */
    public static Result detectWithRanges(String content, List<PiiRegistry.Pattern> patterns,
                                          List<int[]> existingRanges) {
        List<PiiRegistry.Pattern> active =
            patterns != null ? patterns : patternsForContent(content);
        if (active.isEmpty()) {
            return new Result(Collections.<CountryMatch>emptyList(), Collections.<int[]>emptyList());
        }

        List<TableScope> tables = tableScopes(content);
        List<int[]> activeExisting = new ArrayList<>();
        if (existingRanges != null) activeExisting.addAll(existingRanges);
        List<int[]> superseded = new ArrayList<>();
        List<int[]> claimed = new ArrayList<>();
        List<CountryMatch> found = new ArrayList<>();
        List<int[]> nearMisses = new ArrayList<>();
        Map<String, Predicate<String>> checksums = PiiChecksums.functions();

        for (PiiRegistry.Pattern pattern : active) {
            Matcher m = COMPILED.get(pattern.name).matcher(content);
            while (m.find()) {
                int start = m.start();
                int end = m.end();
                if (start == end) continue;

                // Rules 3, 7 and 7b.
                if (pattern.requiresKeyword && !pattern.keywords.isEmpty()) {
                    List<String> all = allKeywordsOf(pattern);
                    boolean ok = hasWholeWordContextAround(content, start, end, pattern.wholeWordKeywords);
                    if (!ok) {
                        Boolean column = columnVerdict(content, tables, start, end, all, specificKeywords(all));
                        ok = column != null ? column : hasNearbyContext(content, start, end, pattern.keywords);
                    }
                    if (!ok) continue;
                    if (labelledAsReference(content, start, end, pattern.keywords)) continue;
                }

                // Rule 4, and rule 6's candidate.
                if (pattern.checksumRequired && pattern.checksum != null) {
                    Predicate<String> fn = checksums.get(pattern.checksum);
                    if (fn != null && !fn.test(m.group())) {
                        if (pattern.nearMissFallback) {
                            List<String> extra = pattern.nearMissKeywords.isEmpty()
                                ? pattern.keywords : pattern.nearMissKeywords;
                            List<String> vocabulary = new ArrayList<>(NATIONAL_ID_KEYWORDS);
                            vocabulary.addAll(extra);
                            if (hasContextAround(content, start, end, vocabulary)) {
                                nearMisses.add(new int[] {start, end});
                            }
                        }
                        continue;
                    }
                }

                // Rule 5.
                List<int[]> overlapping = new ArrayList<>();
                for (int[] r : activeExisting) if (start < r[1] && end > r[0]) overlapping.add(r);
                for (int[] r : claimed) if (start < r[1] && end > r[0]) overlapping.add(r);

                if (!overlapping.isEmpty()) {
                    boolean supersedesAll = true;
                    for (int[] r : overlapping) {
                        int[] core = trimmedCore(content, r[0], r[1]);
                        if (!(start <= core[0] && end >= core[1])) { supersedesAll = false; break; }
                    }
                    if (!supersedesAll) continue;
                    for (int[] o : overlapping) {
                        for (int i = 0; i < activeExisting.size(); i++) {
                            int[] r = activeExisting.get(i);
                            if (r[0] == o[0] && r[1] == o[1]) {
                                superseded.add(activeExisting.remove(i));
                                break;
                            }
                        }
                        for (int i = 0; i < claimed.size(); i++) {
                            int[] r = claimed.get(i);
                            if (r[0] == o[0] && r[1] == o[1]) { claimed.remove(i); break; }
                        }
                        for (int i = 0; i < found.size(); i++) {
                            CountryMatch f = found.get(i);
                            if (f.startIndex == o[0] && f.endIndex == o[1]) { found.remove(i); break; }
                        }
                    }
                }

                claimed.add(new int[] {start, end});
                found.add(new CountryMatch(pattern.name, pattern.country, pattern.label,
                    pattern.type, pattern.redaction, start, end));
            }
        }

        // Rule 6, last: a near miss can only ever fill a hole.
        List<int[]> taken = new ArrayList<>(activeExisting);
        taken.addAll(claimed);
        for (int[] c : nearMisses) {
            boolean clash = false;
            for (int[] t : taken) if (c[0] < t[1] && c[1] > t[0]) { clash = true; break; }
            if (clash) continue;
            taken.add(c);
            found.add(new CountryMatch(PiiRegistry.NEAR_MISS_TYPE, "", "NATIONAL_ID",
                PiiRegistry.NEAR_MISS_TYPE, PiiRegistry.NEAR_MISS_REDACTION, c[0], c[1]));
        }

        found.sort((a, b) -> Integer.compare(a.startIndex, b.startIndex));
        return new Result(found, superseded);
    }

    /** Turn country matches into redaction spans. */
    public static List<RedactionSpan> redactionSpansOf(List<CountryMatch> matches) {
        List<RedactionSpan> spans = new ArrayList<>(matches.size());
        for (CountryMatch m : matches) spans.add(new RedactionSpan(m.startIndex, m.endIndex, m.redaction));
        return spans;
    }

    /**
     * Replace every span with its redaction, right to left.
     *
     * <p>Right to left is what keeps the earlier indices valid, and splicing
     * whole spans in one pass is what guarantees no partial redaction: a digit
     * can never be left standing beside a redaction token, because nothing is
     * ever matched against text a previous replacement has already rewritten.
     */
    public static String applyRedactions(String text, List<RedactionSpan> spans) {
        if (spans.isEmpty()) return text;
        List<RedactionSpan> ordered = new ArrayList<>(spans);
        ordered.sort((a, b) -> Integer.compare(a.startIndex, b.startIndex));
        String out = text;
        for (int i = ordered.size() - 1; i >= 0; i--) {
            RedactionSpan s = ordered.get(i);
            out = out.substring(0, s.startIndex) + s.redaction + out.substring(s.endIndex);
        }
        return out;
    }
}
