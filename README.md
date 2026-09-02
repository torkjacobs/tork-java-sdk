# Tork Governance Java SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Java applications.

## Installation

### Maven

```xml
<dependency>
    <groupId>com.torknetwork</groupId>
    <artifactId>tork-governance</artifactId>
    <version>0.2.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.torknetwork:tork-governance:0.2.0'
```

## Quick Start

```java
import com.tork.governance.Tork;
import com.tork.governance.GovernanceResult;

public class Example {
    public static void main(String[] args) {
        Tork tork = new Tork();

        // Govern text containing PII
        GovernanceResult result = tork.govern("My email is test@example.com");

        System.out.println(result.getOutput());  // "My email is [EMAIL_REDACTED]"
        System.out.println(result.hasPII());      // true
        System.out.println(result.getAction());   // REDACT
        System.out.println(result.getReceipt().getReceiptId()); // "rcpt_..."
    }
}
```

## Regional PII Detection (v1.1)

Activate country-specific and industry-specific PII patterns:

```java
Tork tork = new Tork();

// UAE regional detection — Emirates ID, +971 phone, PO Box
GovernanceResult result = tork.govern(
    "Emirates ID: 784-1234-1234567-1",
    List.of("ae"),
    null
);

// Multi-region + industry
GovernanceResult result = tork.govern(
    "Aadhaar: 1234 5678 9012, ICD-10: J45.20",
    List.of("in"),
    "healthcare"
);

// Available regions: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR
// Available industries: healthcare, finance, legal
```

## PII Types Detected

Tier 1 basic vocabulary — the same 10 types, with the same string codes and
redaction labels, as the JS and Go SDKs. This SDK does **not** carry the
Python SDK's regional/industry pattern tier (AU/US/GB/EU/AE/... profiles) —
see [Regional PII Detection](#regional-pii-detection-v11) above for this
SDK's separate, older regional mechanism.

| Type | Code | Pattern | Redaction |
|------|------|---------|-----------|
| SSN | `ssn` | `XXX-XX-XXXX` | `[SSN_REDACTED]` |
| Credit Card | `credit_card` | `4111-1111-1111-1111` | `[CARD_REDACTED]` |
| Email | `email` | `user@domain.com` | `[EMAIL_REDACTED]` |
| Phone | `phone` | `555-123-4567` | `[PHONE_REDACTED]` |
| Address | `address` | `123 Main Street` | `[ADDRESS_REDACTED]` |
| IP Address | `ip_address` | `192.168.1.1` | `[IP_REDACTED]` |
| Date of Birth | `date_of_birth` | `MM/DD/YYYY` | `[DOB_REDACTED]` |
| Passport | `passport` | `AB1234567` | `[PASSPORT_REDACTED]` |
| Driver's License | `drivers_license` | `D1234567` | `[DL_REDACTED]` |
| Bank Account | `bank_account` | `12345678901234` | `[ACCOUNT_REDACTED]` |

## Scanning tool results

A tool result returned by an MCP server — or any external system you do not
control — is untrusted input that is about to be appended to a model's
context. `Tork#scanToolResult` scans it first, on-device, for PII and prompt
injection:

```java
import com.tork.governance.*;

Tork tork = new Tork();

GovernedToolResultScanResult scan = tork.scanToolResult(
    new ToolResultScanInput("lookup_customer", "mcp://crm.internal/customers", toolResult),
    new ToolResultScanOptions().setBlockOnInjection(true)
);

if (scan.isBlocked()) {
    log.warn(scan.getReason());       // do not append anything
} else {
    appendToContext(scan.getSanitized()); // PII masked in place
}

scan.getFindings();
// [ToolResultFinding{kind=PII, type='email', count=1, location='$.content[0].text'},
//  ToolResultFinding{kind=INJECTION, type='heuristic:instruction_override', count=1, location='$.content[0].text'}]
```

There is also a standalone `ToolResultScanner.scanToolResult(input, options)`
static method with the same signature that returns a `ToolResultScanResult`
(`sanitized`/`findings`/`blocked`/`reason`) and produces no receipt.

- **PII uses the same on-device detector as `govern()`** (`PIIDetector`) — same patterns, same redaction labels. Matches are masked in place; the payload structure is otherwise unchanged, and a clean payload comes back untouched (same `Map`/`List` object identity).
- **Injection detection is heuristic.** A conservative pattern set (`tork-injection-heuristics-v1`) covering instruction-override phrases, role reassignment, and exfiltration URLs. Every injection finding is typed `heuristic:<name>` because that is exactly what it is: a regex match over untrusted text, with false positives and false negatives, not a verified determination. Without `blockOnInjection`, matches are reported and the result is still returned; with it, `sanitized` is `null` so no masked copy can be appended by accident.
- **Zero network calls.** The scan is pure and synchronous — this SDK has no HTTP client anywhere in the scan path.
- **Recorded on the receipt as counts only.** `receipt.getToolResultScan()` carries `attested_by: "client"`, `capture_mode: "edge"`, the tool name and server URI, counts by kind and type, the blocked flag, and the SDK version. It never carries the payload, a matched value, or a location path. `ToolResultScanReceiptBlock#toJson()` emits this as snake_case, alphabetically-ordered JSON with `reason`/`server_uri` omitted (not nulled) when absent — the byte-identical cross-SDK artifact.
- **Action mapping** on `Tork#scanToolResult`'s receipt (fixed, not `TorkConfig.defaultAction`): `blocked` → `DENY`, an injection finding present → `ESCALATE`, otherwise a PII finding present → `REDACT`, otherwise → `ALLOW`.

**This is a client-side, client-attested control.** The scan runs in your process, and the receipt says so: Tork did not execute it and cannot verify it ran at all — the same honest boundary as every other edge attestation this SDK produces. **Gateway-side enforcement, where a caller cannot skip the scan, is a separate and later control.** Do not read a `tool_result_scan` block as proof that every tool result reaching a model was scanned; read it as a record of the scans a caller chose to run and report.

## Framework Integration

### Spring Boot

```java
import com.tork.governance.middleware.SpringBootFilter;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<SpringBootFilter> torkFilter() {
        FilterRegistrationBean<SpringBootFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SpringBootFilter());
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);
        return registration;
    }
}
```

Access the governance result in your controller:

```java
@RestController
@RequestMapping("/api")
public class ChatController {

    @PostMapping("/chat")
    public ResponseEntity<?> chat(HttpServletRequest request, @RequestBody ChatRequest body) {
        GovernanceResult result = (GovernanceResult) request.getAttribute("torkResult");

        if (result != null && result.hasPII()) {
            // PII was detected and redacted
            log.info("PII detected: {}", result.getPiiTypes());
        }

        // Process with governed content
        return ResponseEntity.ok(processChat(body));
    }
}
```

### Quarkus (JAX-RS)

```java
import com.tork.governance.middleware.QuarkusFilter;

// The filter is auto-registered via @Provider annotation
// Or register manually:

@ApplicationPath("/api")
public class MyApplication extends Application {
    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(QuarkusFilter.class);
        // ... other resources
        return classes;
    }
}
```

Access in resource:

```java
@Path("/chat")
public class ChatResource {

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response chat(@Context ContainerRequestContext ctx, String body) {
        GovernanceResult result = (GovernanceResult) ctx.getProperty("torkResult");
        // Use governed content
        return Response.ok(processChat(body)).build();
    }
}
```

### Micronaut

```java
import com.tork.governance.middleware.MicronautFilter;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.HttpServerFilter;

@Filter("/api/**")
public class TorkMicronautFilter implements HttpServerFilter {

    private final MicronautFilter torkFilter = new MicronautFilter();

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request,
                                                       ServerFilterChain chain) {
        // Implement filter logic using torkFilter
        return chain.proceed(request);
    }
}
```

## Configuration

```java
import com.tork.governance.Tork;
import com.tork.governance.GovernanceAction;

// Default configuration
Tork tork = new Tork();

// With API key (for future cloud features)
Tork torkWithKey = new Tork("your-api-key");

// With custom configuration
Tork.TorkConfig config = new Tork.TorkConfig()
    .setDefaultAction(GovernanceAction.DENY)  // Block PII instead of redacting
    .setPolicyVersion("2.0.0");

Tork customTork = new Tork(null, config);
```

## Governance Actions

| Action | Description |
|--------|-------------|
| `ALLOW` | No PII detected, input passes through unchanged |
| `REDACT` | PII detected and replaced with redaction placeholders |
| `DENY` | Request blocked (when configured) |
| `ESCALATE` | Requires human review (when configured) |

## Receipts

Every governance operation generates a cryptographic receipt:

```java
GovernanceResult result = tork.govern("SSN: 123-45-6789");
Receipt receipt = result.getReceipt();

System.out.println(receipt.getReceiptId());     // "rcpt_abc123..."
System.out.println(receipt.getTimestamp());     // "2024-01-30T12:00:00Z"
System.out.println(receipt.getInputHash());     // "sha256:..."
System.out.println(receipt.getOutputHash());    // "sha256:..."
System.out.println(receipt.getAction());        // REDACT

// Verify integrity
boolean validInput = receipt.verifyInput("SSN: 123-45-6789");
boolean validOutput = receipt.verifyOutput("SSN: [SSN_REDACTED]");
```

## Statistics

```java
Tork tork = new Tork();

// Make some governance calls
tork.govern("test@example.com");
tork.govern("Clean text");
tork.govern("SSN: 123-45-6789");

// Get statistics
System.out.println("Total calls: " + tork.getTotalCalls());
System.out.println("PII detected: " + tork.getTotalPIIDetected());
System.out.println("Avg time (ns): " + tork.getAverageProcessingTimeNanos());

// Reset if needed
tork.resetStats();
```

## Requirements

- Java 11 or higher
- No external dependencies for core functionality
- Optional: Spring Web, JAX-RS API, or Micronaut for framework integration

## License

MIT License - see LICENSE file for details.
