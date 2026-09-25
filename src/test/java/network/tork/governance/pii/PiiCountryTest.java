package network.tork.governance.pii;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Country-layer parity tests.
 *
 * <p>The fixtures are generated from the cloud's own evidence, not written here:
 *
 * <ul>
 *   <li>{@code pii_unit_cases.json} -- one valid sample per registry pattern, a
 *       checksum-broken variant for each pattern whose checksum is a gate, and
 *       the Indonesian boundary cases.</li>
 *   <li>{@code pii_vectors.json} -- all 2,092 inputs of the cloud's golden
 *       snapshot: every country-corpus sentence for all 249 ISO jurisdictions,
 *       and the whole 1,523-line business false-positive corpus.</li>
 * </ul>
 *
 * <p>{@code expectedOutput} is the COUNTRY LAYER alone. Where the cloud's own
 * output differs, the case carries {@code cloudOutput} and a {@code divergence}
 * naming the cause.
 */
class PiiCountryTest {

    private static final String NIK = "3171010101900001";
    private static final Gson GSON = new Gson();

    static final class UnitCase {
        String pattern; String country; String label; String redaction;
        String input; String sample;
        @SerializedName("expectDetected") boolean expectDetected;
        String note;
    }

    static final class Vector {
        String id; String kind; String input;
        @SerializedName("expectedOutput") String expectedOutput;
        @SerializedName("expectedRegions") List<String> expectedRegions;
        @SerializedName("expectedLabels") List<String> expectedLabels;
        @SerializedName("expectedNames") List<String> expectedNames;
        @SerializedName("cloudOutput") String cloudOutput;
        String divergence;
    }

    static final class VectorFile {
        @SerializedName("bundleVersion") String bundleVersion;
        @SerializedName("contentHash") String contentHash;
        List<Vector> cases;
    }

    private static <T> T fixture(String name, Class<T> type) {
        return GSON.fromJson(new InputStreamReader(
            PiiCountryTest.class.getResourceAsStream("/" + name), StandardCharsets.UTF_8), type);
    }

    private static final VectorFile V = fixture("pii_vectors.json", VectorFile.class);
    private static final UnitCase[] UNITS = fixture("pii_unit_cases.json", UnitCase[].class);

    private static String redact(String s) {
        List<PiiCountry.CountryMatch> m = PiiCountry.detect(s);
        return PiiCountry.applyRedactions(s, PiiCountry.redactionSpansOf(m));
    }

    private static List<String> distinct(List<PiiCountry.CountryMatch> ms, boolean label) {
        List<String> out = new ArrayList<>();
        for (PiiCountry.CountryMatch m : ms) {
            String v = label ? m.label : m.name;
            if (!out.contains(v)) out.add(v);
        }
        return out;
    }

    // ── the bundle ──────────────────────────────────────────────────────────

    @Test
    void isTheVersionAndContentTheFixturesWereGeneratedFrom() {
        assertEquals(V.bundleVersion, PiiRegistry.VERSION);
        assertEquals(V.contentHash, PiiRegistry.CONTENT_HASH);
    }

    @Test
    void carries54PatternsAcross24ProfilesWith51Signals() {
        assertEquals(54, PiiRegistry.PATTERNS.size());
        assertEquals(24, PiiRegistry.COUNTRIES.size());
        assertEquals(51, PiiRegistry.SIGNALS.size());
    }

    @Test
    void carriesExactlyThreeAlwaysOnPatternsAllAustralian() {
        List<String> names = PiiCountry.alwaysOnPatterns().stream().map(p -> p.name)
            .collect(Collectors.toList());
        assertEquals(Arrays.asList("au_tfn", "au_abn", "au_medicare"), names);
    }

    @Test
    void coversIndonesiaAddedIn110() {
        PiiRegistry.Country id = PiiRegistry.COUNTRIES.stream()
            .filter(c -> c.code.equals("ID")).findFirst().orElse(null);
        assertNotNull(id, "Indonesia is missing from the bundle");
        assertTrue(id.patterns.contains("id_nik"));
        PiiRegistry.Pattern nik = PiiRegistry.PATTERNS.stream()
            .filter(p -> p.name.equals("id_nik")).findFirst().orElse(null);
        assertNotNull(nik);
        assertEquals("NIK", nik.label);
        assertTrue(nik.wholeWordKeywords.contains("nik"));
    }

    @Test
    void readsItsWindowsFromTheBundleAndTheyAreNotAllTheSame() {
        assertEquals(60, PiiCountry.KEYWORD_WINDOW_BEFORE);
        assertEquals(40, PiiCountry.KEYWORD_WINDOW_AFTER);
        assertEquals(60, PiiCountry.CONTEXT_WINDOW);
        assertFalse(PiiCountry.KEYWORD_WINDOW_BEFORE == PiiCountry.KEYWORD_WINDOW_AFTER);
    }

    @Test
    void namesAChecksumFunctionForEveryPatternThatDeclaresOne() {
        Map<String, java.util.function.Predicate<String>> fns = PiiChecksums.functions();
        for (PiiRegistry.Pattern p : PiiRegistry.PATTERNS) {
            if (p.checksum == null) continue;
            assertNotNull(fns.get(p.checksum), p.name + " -> " + p.checksum);
        }
    }

    @Test
    void usesOnlyThePortableRegexSubset() {
        String[][] forbidden = {
            {"(?=", "lookahead"}, {"(?!", "negative lookahead"}, {"(?<=", "lookbehind"},
            {"(?<!", "negative lookbehind"}, {"\\p{", "unicode property escape"}, {"(?>", "atomic group"},
        };
        List<String> sources = new ArrayList<>();
        for (PiiRegistry.Pattern p : PiiRegistry.PATTERNS) sources.add(p.regex);
        for (PiiRegistry.Signal s : PiiRegistry.SIGNALS) sources.add(s.regex);
        for (String src : sources) {
            for (String[] f : forbidden) {
                assertFalse(src.contains(f[0]), src + " uses " + f[1]);
            }
        }
    }

    // ── per-pattern unit cases ──────────────────────────────────────────────

    @Test
    void perPatternUnitCases() {
        assertTrue(UNITS.length > 0);
        for (UnitCase c : UNITS) {
            PiiRegistry.Pattern p = PiiRegistry.PATTERNS.stream()
                .filter(x -> x.name.equals(c.pattern)).findFirst().orElse(null);
            assertNotNull(p, c.pattern + " is not in the bundle");
            PiiCountry.CountryMatch hit = PiiCountry.detect(c.input, Collections.singletonList(p))
                .stream().filter(m -> m.name.equals(c.pattern)).findFirst().orElse(null);
            if (c.expectDetected) {
                assertNotNull(hit, "expected " + c.pattern + " to match " + c.input);
                assertEquals(c.sample, c.input.substring(hit.startIndex, hit.endIndex));
                assertEquals(c.redaction, hit.redaction);
            } else {
                assertNull(hit, "expected " + c.pattern + " NOT to match " + c.input);
            }
        }
    }

    // ── golden-snapshot parity ──────────────────────────────────────────────

    @Test
    void reproducesTheCloudOnEveryCorpusVector() {
        List<String> failures = new ArrayList<>();
        int checked = 0;
        for (Vector c : V.cases) {
            if ("business-fp".equals(c.kind)) continue;
            checked++;
            List<PiiCountry.CountryMatch> matches = PiiCountry.detect(c.input);
            String out = PiiCountry.applyRedactions(c.input, PiiCountry.redactionSpansOf(matches));
            if (!PiiCountry.inferRegions(c.input).equals(c.expectedRegions)) failures.add(c.id + " activation");
            if (!out.equals(c.expectedOutput)) failures.add(c.id + " redaction");
            if (!distinct(matches, true).equals(c.expectedLabels)) failures.add(c.id + " labels");
            if (!distinct(matches, false).equals(c.expectedNames)) failures.add(c.id + " names");
        }
        assertTrue(checked > 500, "only " + checked + " corpus vectors");
        assertEquals(Collections.emptyList(), failures);
    }

    @Test
    void addsNoFalsePositiveToTheBusinessCorpus() {
        List<String> bad = new ArrayList<>();
        List<String> drift = new ArrayList<>();
        int n = 0;
        for (Vector c : V.cases) {
            if (!"business-fp".equals(c.kind)) continue;
            n++;
            if (!PiiCountry.detect(c.input).isEmpty()) bad.add(c.id);
            if (!PiiCountry.inferRegions(c.input).equals(c.expectedRegions)) drift.add(c.id);
        }
        assertTrue(n > 1500, "business corpus = " + n + " lines");
        assertEquals(Collections.emptyList(), bad);
        assertEquals(Collections.emptyList(), drift);
    }

    @Test
    void theAuBundleGapIsClosedOnlyL0DivergencesRemain() {
        Set<String> gaps = new TreeSet<>();
        for (Vector c : V.cases) {
            if (c.divergence == null) continue;
            assertTrue(c.divergence.startsWith("L0:") || c.divergence.startsWith("BUNDLE GAP:"),
                c.id + ": unexplained divergence");
            if (c.divergence.startsWith("BUNDLE GAP:")) gaps.add(c.id.split("/")[1]);
        }
        // Bundle 1.2.0 ships au_tfn, au_abn and au_medicare as alwaysOn patterns,
        // so the cause that used to name them is gone; every remaining
        // divergence is the cloud-only L0 layer this bundle never carried.
        assertEquals(Collections.emptySet(), gaps);
    }

    @Test
    void nothingIsEverPartiallyRedacted() {
        java.util.regex.Pattern bad =
            java.util.regex.Pattern.compile("\\d\\[[A-Z_]+_REDACTED\\]|\\[[A-Z_]+_REDACTED\\]\\d");
        for (Vector c : V.cases) {
            List<PiiCountry.CountryMatch> matches = PiiCountry.detect(c.input);
            String out = PiiCountry.applyRedactions(c.input, PiiCountry.redactionSpansOf(matches));
            assertFalse(bad.matcher(out).find(), c.id + ": " + out);
            for (PiiCountry.CountryMatch m : matches) {
                String raw = c.input.substring(m.startIndex, m.endIndex);
                assertFalse(out.contains(raw), c.id + ": " + raw + " survived");
            }
        }
    }

    // ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────

    @Test
    void detectsTheShortSpellingWhichIsAWholeWordKeywordOnly() {
        String s = "NIK " + NIK + " untuk pendaftaran rekening di Jakarta, Indonesia.";
        assertEquals(Collections.singletonList("ID"), PiiCountry.inferRegions(s));
        assertEquals("NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.", redact(s));
    }

    @Test
    void detectsTheLongSpellingWhichIsAnOrdinarySubstringKeyword() {
        assertTrue(redact("Nomor Induk Kependudukan " + NIK + " untuk pendaftaran.")
            .contains("[NIK_REDACTED]"));
    }

    @Test
    void nikInsideAnOrdinaryIndonesianWordDoesNotOpenTheGate() {
        for (String word : new String[] {"teknik", "elektronik", "klinik", "pabrik", "piknik"}) {
            assertTrue(PiiCountry.detect("Faktur " + word + " " + NIK + " untuk pelanggan.").isEmpty(),
                word + " opened the gate");
        }
    }

    @Test
    void aBareNikIsNotRedacted() {
        assertTrue(PiiCountry.detect(NIK).isEmpty());
    }

    // ── the rules 1.1.0 added to the SDK half of the contract ───────────────

    @Test
    void rule6ChecksumFailingIdentifierIsRedactedGenerically() {
        String out = redact("South African ID number 8001015009088 for the FICA check.");
        assertFalse(out.contains("8001015009088"));
        assertTrue(out.contains("[NATIONAL_ID_REDACTED]"));
    }

    @Test
    void rule7ColumnHeaderIsTheContextForABareValueCell() {
        String csv = String.join("\n", "Name,CNIC,City", "Ali,42201-1234567-1,Karachi",
            "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan");
        assertTrue(PiiCountry.isTable(csv));
        assertFalse(redact(csv).contains("42201-1234567-1"));
    }

    @Test
    void rule7GenericHeaderDoesNotActAsContext() {
        String csv = String.join("\n", "Name,Order ID Number,City", "Ali,42201-1234567-1,Karachi",
            "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan");
        assertTrue(PiiCountry.detect(csv).isEmpty());
    }

    @Test
    void rule7bCloserCommercialLabelClosesTheGate() {
        String s = "Please do not send your CNIC. Use the job number 4220112345671.";
        int at = s.indexOf("4220112345671");
        assertTrue(PiiCountry.labelledAsReference(s, at, at + 13, Collections.singletonList("cnic")));
        assertTrue(redact(s).contains("4220112345671"));
    }

    @Test
    void rule7bCanOnlyCloseAGateNeverOpenOne() {
        assertTrue(PiiCountry.detect("Order 12345678901234 with no identifier word anywhere.").isEmpty());
    }

    @Test
    void rule5CountryMatchSupersedesAWiderL0Range() {
        String s = "CPF 529.982.247-25 para a nota fiscal no Brasil.";
        int at = s.indexOf("529.982.247-25");
        PiiCountry.Result res = PiiCountry.detectWithRanges(
            s, null, Collections.singletonList(new int[] {at - 1, at + 14}));
        assertTrue(res.matches.stream().anyMatch(m -> m.name.equals("br_cpf")));
        assertEquals(1, res.supersededRanges.size());
    }

    @Test
    void wholeWordMatchingRespectsBoundaries() {
        assertTrue(PiiCountry.hasWholeWordContextAround("nik 123", 4, 7, Collections.singletonList("nik")));
        assertFalse(PiiCountry.hasWholeWordContextAround("teknik 123", 7, 10, Collections.singletonList("nik")));
    }

    // ── rule 1a: AU's alwaysOn patterns, added to the bundle in 1.2.0 ────────

    @Test
    void rule1aAbnIsDetectedWithNoRegionActivated() {
        String s = "Supplier ABN 51 824 753 556 appears on the Australian invoice.";
        // The ABN's own shape and keyword activate no country (README, rule 1a):
        // an 11-digit run and the word "ABN" match none of AU's activation signals.
        assertEquals(Collections.emptyList(), PiiCountry.inferRegions(s));
        assertEquals("Supplier ABN [ABN_REDACTED] appears on the Australian invoice.", redact(s));
    }

    @Test
    void rule1aTfnAndMedicareAreDetectedWhetherOrNotAuActivates() {
        assertEquals("My TFN is [TFN_REDACTED] for the ATO return.",
            redact("My TFN is 876543210 for the ATO return."));
        assertEquals("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.",
            redact("Patient Medicare number 2123456701 for the bulk-billed visit."));
    }

    @Test
    void rule4TfnFailingItsRequiredChecksumFallsBackToANearMissNotAFalseNegative() {
        String out = redact("My tax file number is 876 543 211 for the ATO return.");
        assertFalse(out.contains("876 543 211"));
        assertFalse(out.contains("[TFN_REDACTED]"), "a checksum-failing TFN is not that country's identifier");
        assertTrue(out.contains("[NATIONAL_ID_REDACTED]"));
    }

    @Test
    void abnFailingItsRequiredChecksumIsDroppedNotNearMissed() {
        // ABN's kind is "company", not one of the 10 person-identifying kinds
        // nearMissFallback covers (README rule 6) -- a bad check digit is a
        // data-quality problem here, not a privacy one, so nothing is redacted.
        assertTrue(PiiCountry.detect("Supplier ABN 51 824 753 557 appears on the Australian invoice.").isEmpty());
    }

    @Test
    void rule1aMedicareChecksumIsAdvisoryAndNeverRejectsAMatch() {
        String out = redact("Patient Medicare number 2123 45671 1 for the bulk-billed visit.");
        assertEquals("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.", out);
    }
}
