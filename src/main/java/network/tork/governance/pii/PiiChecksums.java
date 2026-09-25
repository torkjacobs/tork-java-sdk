package network.tork.governance.pii;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Check digits for the country registry.
 *
 * <p>The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
 * the eleven that reduce to them; the other nine are marked {@code kind:"custom"}
 * and carry no specification, so they are ported here by hand from the cloud's
 * {@code lib/pii/checksums.ts} -- the single implementation the cloud and the
 * country corpus both use. Keeping the arithmetic identical is what makes a
 * receipt block from this SDK byte-identical to one from the JavaScript SDK.
 *
 * <p>Every method is pure: a String in, a boolean out. No I/O, no clock.
 */
public final class PiiChecksums {

    private PiiChecksums() {}

    private static String digitsOf(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') sb.append(c);
        }
        return sb.toString();
    }

    /** Remainder of a long decimal digit string modulo m, digit by digit. */
    private static int modDigits(String digits, int m) {
        int r = 0;
        for (int i = 0; i < digits.length(); i++) {
            r = (r * 10 + (digits.charAt(i) - '0')) % m;
        }
        return r;
    }

    private static boolean allSameDigit(String d) {
        if (d.isEmpty()) return false;
        for (int i = 1; i < d.length(); i++) {
            if (d.charAt(i) != d.charAt(0)) return false;
        }
        return true;
    }

    private static String stripWhitespaceUpper(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isWhitespace(c)) sb.append(Character.toUpperCase(c));
        }
        return sb.toString();
    }

    /** Luhn / ISO-IEC 7812-1 mod-10. */
    public static boolean luhn(String input) {
        String d = digitsOf(input);
        if (d.length() < 2) return false;
        int sum = 0;
        boolean dbl = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int n = d.charAt(i) - '0';
            if (dbl) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    private static final int[][] VERHOEFF_MUL = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
        {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
        {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
        {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
        {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
        {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
        {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
        {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
        {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
        {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
    };

    private static final int[][] VERHOEFF_PERM = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
        {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
        {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
        {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
        {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
        {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
        {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
        {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
    };

    /** Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018). */
    public static boolean verhoeff(String input) {
        String d = digitsOf(input);
        int c = 0;
        for (int i = 0; i < d.length(); i++) {
            int digit = d.charAt(d.length() - 1 - i) - '0';
            c = VERHOEFF_MUL[c][VERHOEFF_PERM[i % 8][digit]];
        }
        return c == 0;
    }

    /** Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0. */
    public static boolean auTfn(String input) {
        String d = digitsOf(input);
        if (d.length() != 9) return false;
        int[] w = {1, 4, 3, 7, 5, 8, 6, 9, 10};
        int sum = 0;
        for (int i = 0; i < 9; i++) sum += (d.charAt(i) - '0') * w[i];
        return sum % 11 == 0;
    }

    /** Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19, mod 89. */
    public static boolean auAbn(String input) {
        String d = digitsOf(input);
        if (d.length() != 11) return false;
        int[] w = {10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19};
        int sum = (d.charAt(0) - '0' - 1) * w[0];
        for (int i = 1; i < 11; i++) sum += (d.charAt(i) - '0') * w[i];
        return sum % 89 == 0;
    }

    /** Australian Medicare card number (Services Australia). */
    public static boolean auMedicare(String input) {
        String d = digitsOf(input);
        if (d.length() < 10) return false;
        if ("23456".indexOf(d.charAt(0)) < 0) return false;
        int[] w = {1, 3, 7, 9, 1, 3, 7, 9};
        int sum = 0;
        for (int i = 0; i < 8; i++) sum += (d.charAt(i) - '0') * w[i];
        return sum % 10 == d.charAt(8) - '0';
    }

    /** UK NHS number (NHS Data Model and Dictionary): weights 10..2, check = 11 - (sum mod 11). */
    public static boolean ukNhs(String input) {
        String d = digitsOf(input);
        if (d.length() != 10) return false;
        int sum = 0;
        for (int i = 0; i < 9; i++) sum += (d.charAt(i) - '0') * (10 - i);
        int check = 11 - (sum % 11);
        if (check == 11) check = 0;
        if (check == 10) return false;
        return check == d.charAt(9) - '0';
    }

    /** Brazil CPF (Receita Federal): two sequential mod-11 check digits. */
    public static boolean brCpf(String input) {
        String d = digitsOf(input);
        if (d.length() != 11 || allSameDigit(d)) return false;
        return cpfCheck(d, 9) == d.charAt(9) - '0' && cpfCheck(d, 10) == d.charAt(10) - '0';
    }

    private static int cpfCheck(String d, int len) {
        int sum = 0;
        for (int i = 0; i < len; i++) sum += (d.charAt(i) - '0') * (len + 1 - i);
        int r = (sum * 10) % 11;
        return r == 10 ? 0 : r;
    }

    /** Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight vectors. */
    public static boolean brCnpj(String input) {
        String d = digitsOf(input);
        if (d.length() != 14 || allSameDigit(d)) return false;
        int[] first = {5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        int[] second = {6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        return cnpjCheck(d, first) == d.charAt(12) - '0'
            && cnpjCheck(d, second) == d.charAt(13) - '0';
    }

    private static int cnpjCheck(String d, int[] weights) {
        int sum = 0;
        for (int i = 0; i < weights.length; i++) sum += (d.charAt(i) - '0') * weights[i];
        int r = sum % 11;
        return r < 2 ? 0 : 11 - r;
    }

    /** Japan My Number (MIC Ordinance No. 85 of 2014). */
    public static boolean jpMyNumber(String input) {
        String d = digitsOf(input);
        if (d.length() != 12) return false;
        int sum = 0;
        for (int n = 1; n <= 11; n++) {
            int p = d.charAt(11 - n) - '0';
            int q = n <= 6 ? n + 1 : n - 5;
            sum += p * q;
        }
        int r = sum % 11;
        int check = r <= 1 ? 0 : 11 - r;
        return check == d.charAt(11) - '0';
    }

    private static final Pattern CN_SHAPE = Pattern.compile("^\\d{17}[\\dX]$");

    /** China resident ID (GB 11643-1999): ISO 7064 MOD 11-2, check character may be X. */
    public static boolean cnResidentId(String input) {
        String s = stripWhitespaceUpper(input);
        if (!CN_SHAPE.matcher(s).matches()) return false;
        int[] w = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
        int sum = 0;
        for (int i = 0; i < 17; i++) sum += (s.charAt(i) - '0') * w[i];
        return "10X98765432".charAt(sum % 11) == s.charAt(17);
    }

    /**
     * Korea RRN, for numbers issued before 20 Oct 2020.
     *
     * <p>ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are
     * randomly assigned and carry no check digit.
     */
    public static boolean krRrn(String input) {
        String d = digitsOf(input);
        if (d.length() != 13) return false;
        int[] w = {2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5};
        int sum = 0;
        for (int i = 0; i < 12; i++) sum += (d.charAt(i) - '0') * w[i];
        return (11 - (sum % 11)) % 10 == d.charAt(12) - '0';
    }

    private static final Pattern SG_SHAPE = Pattern.compile("^[STFGM]\\d{7}[A-Z]$");

    /** Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent letter table. */
    public static boolean sgNric(String input) {
        String s = stripWhitespaceUpper(input);
        if (!SG_SHAPE.matcher(s).matches()) return false;
        int[] w = {2, 7, 6, 5, 4, 3, 2};
        int sum = 0;
        for (int i = 0; i < 7; i++) sum += (s.charAt(1 + i) - '0') * w[i];
        char prefix = s.charAt(0);
        if (prefix == 'T' || prefix == 'G') sum += 4;
        if (prefix == 'M') sum += 3;
        String table;
        if (prefix == 'S' || prefix == 'T') table = "JZIHGFEDCBA";
        else if (prefix == 'M') table = "KLJNPQRTUWX";
        else table = "XWUTRQPNMLK";
        return table.charAt(sum % 11) == s.charAt(8);
    }

    private static final Map<Character, Integer> CF_ODD = new HashMap<>();

    static {
        String digits = "0123456789";
        int[] digitValues = {1, 0, 5, 7, 9, 13, 15, 17, 19, 21};
        for (int i = 0; i < digits.length(); i++) CF_ODD.put(digits.charAt(i), digitValues[i]);
        String letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        int[] letterValues = {1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23};
        for (int i = 0; i < letters.length(); i++) CF_ODD.put(letters.charAt(i), letterValues[i]);
    }

    private static final Pattern CF_SHAPE =
        Pattern.compile("^[A-Z]{6}\\d{2}[A-Z]\\d{2}[A-Z]\\d{3}[A-Z]$");

    /** Italy codice fiscale (Agenzia delle Entrate): odd/even tables, mod 26, check letter. */
    public static boolean itCodiceFiscale(String input) {
        String s = stripWhitespaceUpper(input);
        if (!CF_SHAPE.matcher(s).matches()) return false;
        int sum = 0;
        for (int i = 0; i < 15; i++) {
            char c = s.charAt(i);
            if (i % 2 == 0) sum += CF_ODD.get(c);
            else if (c >= '0' && c <= '9') sum += c - '0';
            else sum += c - 'A';
        }
        return (char) ('A' + (sum % 26)) == s.charAt(15);
    }

    private static final Pattern NIR_SHAPE =
        Pattern.compile("^[12]\\d{2}\\d{2}(\\d{2}|2A|2B)\\d{3}\\d{3}\\d{2}$");

    /** France NIR (Insee): 97-complement, Corsican 2A/2B mapped to 19/18 first. */
    public static boolean frNir(String input) {
        String s = stripWhitespaceUpper(input);
        if (!NIR_SHAPE.matcher(s).matches()) return false;
        s = s.replaceFirst("2A", "19").replaceFirst("2B", "18");
        String body = s.substring(0, 13);
        int key = Integer.parseInt(s.substring(13));
        return 97 - modDigits(body, 97) == key;
    }

    /** Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits. */
    public static boolean deSteuerId(String input) {
        String d = digitsOf(input);
        if (d.length() != 11 || d.charAt(0) == '0') return false;
        int product = 10;
        for (int i = 0; i < 10; i++) {
            int sum = (d.charAt(i) - '0' + product) % 10;
            if (sum == 0) sum = 10;
            product = (sum * 2) % 11;
        }
        int check = 11 - product;
        if (check == 10) check = 0;
        return check == d.charAt(10) - '0';
    }

    /** Thailand national ID (DOPA): weights 13..2, check = (11 - sum mod 11) mod 10. */
    public static boolean thNationalId(String input) {
        String d = digitsOf(input);
        if (d.length() != 13) return false;
        int sum = 0;
        for (int i = 0; i < 12; i++) sum += (d.charAt(i) - '0') * (13 - i);
        return (11 - (sum % 11)) % 10 == d.charAt(12) - '0';
    }

    /** Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- community-sourced. */
    public static boolean caSin(String input) {
        return digitsOf(input).length() == 9 && luhn(input);
    }

    /** South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits. */
    public static boolean zaId(String input) {
        return digitsOf(input).length() == 13 && luhn(input);
    }

    /** UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory. */
    public static boolean aeEmiratesId(String input) {
        String d = digitsOf(input);
        return d.length() == 15 && d.startsWith("784") && luhn(d);
    }

    /** Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory. */
    public static boolean saNationalId(String input) {
        String d = digitsOf(input);
        return d.length() == 10 && (d.charAt(0) == '1' || d.charAt(0) == '2') && luhn(d);
    }

    private static final Map<String, Predicate<String>> FUNCTIONS = new HashMap<>();

    static {
        FUNCTIONS.put("luhn", PiiChecksums::luhn);
        FUNCTIONS.put("verhoeff", PiiChecksums::verhoeff);
        FUNCTIONS.put("au_tfn", PiiChecksums::auTfn);
        FUNCTIONS.put("au_abn", PiiChecksums::auAbn);
        FUNCTIONS.put("au_medicare", PiiChecksums::auMedicare);
        FUNCTIONS.put("uk_nhs", PiiChecksums::ukNhs);
        FUNCTIONS.put("br_cpf", PiiChecksums::brCpf);
        FUNCTIONS.put("br_cnpj", PiiChecksums::brCnpj);
        FUNCTIONS.put("jp_my_number", PiiChecksums::jpMyNumber);
        FUNCTIONS.put("cn_resident_id", PiiChecksums::cnResidentId);
        FUNCTIONS.put("kr_rrn", PiiChecksums::krRrn);
        FUNCTIONS.put("sg_nric", PiiChecksums::sgNric);
        FUNCTIONS.put("it_codice_fiscale", PiiChecksums::itCodiceFiscale);
        FUNCTIONS.put("fr_nir", PiiChecksums::frNir);
        FUNCTIONS.put("de_steuer_id", PiiChecksums::deSteuerId);
        FUNCTIONS.put("th_national_id", PiiChecksums::thNationalId);
        FUNCTIONS.put("ca_sin", PiiChecksums::caSin);
        FUNCTIONS.put("za_id", PiiChecksums::zaId);
        FUNCTIONS.put("ae_emirates_id", PiiChecksums::aeEmiratesId);
        FUNCTIONS.put("sa_national_id", PiiChecksums::saNationalId);
    }

    /** Keyed by the bundle's {@code checksum} field. */
    public static Map<String, Predicate<String>> functions() {
        return java.util.Collections.unmodifiableMap(FUNCTIONS);
    }

    /** The checksum named by the bundle, or {@code null} if it is not implemented. */
    public static Predicate<String> get(String name) {
        return FUNCTIONS.get(name);
    }
}
