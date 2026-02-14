# Tork Governance Java SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Java applications.

## Installation

### Maven

```xml
<dependency>
    <groupId>com.torknetwork</groupId>
    <artifactId>tork-governance</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.torknetwork:tork-governance:0.1.0'
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

| Type | Pattern | Redaction |
|------|---------|-----------|
| SSN | `XXX-XX-XXXX` | `[SSN_REDACTED]` |
| Email | `user@domain.com` | `[EMAIL_REDACTED]` |
| Phone | `555-123-4567` | `[PHONE_REDACTED]` |
| Credit Card | `4111-1111-1111-1111` | `[CARD_REDACTED]` |
| IP Address | `192.168.1.1` | `[IP_REDACTED]` |
| Date of Birth | `MM/DD/YYYY` | `[DOB_REDACTED]` |

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
