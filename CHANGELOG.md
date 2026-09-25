# Changelog

## 0.3.0 - 2026-09-25

### Added
- **PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).**
  The country layer: 24 country profiles, 54 patterns, 20 check digits.
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID. Three patterns
  (`au_tfn`, `au_abn`, `au_medicare`) are `alwaysOn`: they run on every
  document regardless of country activation (`PiiCountry.alwaysOnPatterns()`),
  closing the gap where checksums.json named all three but no country profile
  shipped them.
- New package `network.tork.governance.pii`: `PiiRegistry` (the bundle's 54
  patterns), `PiiActivation` (the 51 signals and the country map),
  `PiiChecksums` (20 algorithms) and `PiiCountry` (the matcher). All pure and
  local: no network, no clock.
- `PIIDetector.DetectionResult` gains `getCountryMatches()`,
  `getCountryLabels()` and `getRegions()`; the existing four-argument
  constructor still works and leaves them empty.
  `detectAndRedact(String, List<String>)` forces a set of country profiles on.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.
- Gson at test scope only, to read the parity fixtures. The published artifact
  gains no new dependency.

### Fixed
- **MAVEN COORDINATE.** The POM declared `network.tork:tork-governance` and the
  README told readers to depend on `com.torknetwork:tork-governance`. Neither
  exists. The artifact published on Maven Central is
  **`io.github.torkjacobs:tork-governance`** (0.1.0). Both are corrected, so
  `mvn deploy` now reaches the coordinate consumers actually resolve. Nothing
  was ever published under the other two group IDs, so no consumer breaks.
- **SDK-JAVA-PARTIAL-REDACTION.** Until 0.2.0 `detectAndRedact` redacted each
  type with its own `Matcher.replaceAll` over text a previous type had already
  rewritten, while the match list carried indices into the *original* text. Two
  types matching overlapping spans could leave half an identifier standing
  beside a redaction token -- digits exposed in output the caller had been told
  was redacted. Every match is now collected against the original text,
  overlaps are resolved before anything is rewritten, and the surviving spans
  are spliced right to left in one pass. `nothingIsEverPartiallyRedacted`
  asserts the invariant across all 2,092 vectors.
- **`redact(String, List<PIIMatch>)` ignored its `matches` argument** and re-ran
  every pattern over already-rewritten text. It now delegates to
  `detectAndRedact`, so there is one implementation of the redaction rules.

### Notes
- This release folds in 0.2.0, which is in this repository but was never
  published to Maven Central (Central is at 0.1.0) and never had a changelog
  entry.
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## 0.1.2 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
