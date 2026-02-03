package com.tork.governance.middleware;

import com.tork.governance.GovernanceResult;
import com.tork.governance.Tork;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Micronaut HttpServerFilter for Tork governance.
 *
 * <p>Filter for governing HTTP request and response content in Micronaut applications.</p>
 *
 * <h2>Usage with Micronaut:</h2>
 * <pre>{@code
 * import io.micronaut.http.annotation.Filter;
 * import io.micronaut.http.filter.HttpServerFilter;
 * import io.micronaut.http.filter.ServerFilterChain;
 * import io.micronaut.http.HttpRequest;
 * import org.reactivestreams.Publisher;
 *
 * @Filter("/api/**")
 * public class TorkMicronautFilter implements HttpServerFilter {
 *
 *     private final MicronautFilter torkFilter = new MicronautFilter();
 *
 *     @Override
 *     public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request,
 *                                                        ServerFilterChain chain) {
 *         return torkFilter.doFilter(request, chain);
 *     }
 * }
 * }</pre>
 *
 * <h2>Accessing governance result in controller:</h2>
 * <pre>{@code
 * @Controller("/api")
 * public class ChatController {
 *     @Post("/chat")
 *     public HttpResponse<?> chat(HttpRequest<?> request, @Body String body) {
 *         GovernanceResult result = request.getAttribute("torkResult", GovernanceResult.class)
 *             .orElse(null);
 *         // Use governed content
 *     }
 * }
 * }</pre>
 */
public class MicronautFilter {

    private final Tork tork;
    private boolean governResponse = true;

    /**
     * Create filter with default Tork instance.
     */
    public MicronautFilter() {
        this.tork = new Tork();
    }

    /**
     * Create filter with API key.
     * @param apiKey the API key
     */
    public MicronautFilter(String apiKey) {
        this.tork = new Tork(apiKey);
    }

    /**
     * Create filter with custom Tork instance.
     * @param tork the Tork instance
     */
    public MicronautFilter(Tork tork) {
        this.tork = tork;
    }

    /**
     * Set whether to govern response content.
     * @param governResponse true to govern responses
     * @return this filter for chaining
     */
    public MicronautFilter setGovernResponse(boolean governResponse) {
        this.governResponse = governResponse;
        return this;
    }

    /**
     * Process and govern request content.
     *
     * <p>This method should be called from a Micronaut HttpServerFilter implementation.</p>
     *
     * @param body the request body as string
     * @return governance result
     */
    public GovernanceResult governRequest(String body) {
        if (body == null || body.isEmpty()) {
            return tork.govern("");
        }
        return tork.govern(body);
    }

    /**
     * Process and govern response content.
     *
     * @param body the response body as string
     * @return governance result
     */
    public GovernanceResult governResponse(String body) {
        if (!governResponse || body == null || body.isEmpty()) {
            return tork.govern(body != null ? body : "");
        }
        return tork.govern(body);
    }

    /**
     * Check if request method typically has a body.
     *
     * @param method HTTP method
     * @return true if method typically has body
     */
    public boolean hasRequestBody(String method) {
        return "POST".equalsIgnoreCase(method) ||
               "PUT".equalsIgnoreCase(method) ||
               "PATCH".equalsIgnoreCase(method);
    }

    /**
     * Get the Tork instance used by this filter.
     * @return the Tork instance
     */
    public Tork getTork() {
        return tork;
    }

    /**
     * Result holder for governed content with metadata.
     */
    public static class FilterResult {
        private final String governedBody;
        private final GovernanceResult result;
        private final boolean blocked;

        public FilterResult(String governedBody, GovernanceResult result, boolean blocked) {
            this.governedBody = governedBody;
            this.result = result;
            this.blocked = blocked;
        }

        public String getGovernedBody() {
            return governedBody;
        }

        public GovernanceResult getResult() {
            return result;
        }

        public boolean isBlocked() {
            return blocked;
        }

        public String getReceiptId() {
            return result.getReceipt().getReceiptId();
        }
    }

    /**
     * Full filter processing for request body.
     *
     * @param body request body
     * @return filter result with governed content and metadata
     */
    public FilterResult processRequest(String body) {
        GovernanceResult result = governRequest(body);
        boolean blocked = result.isDenied();
        return new FilterResult(result.getOutput(), result, blocked);
    }

    /**
     * Full filter processing for response body.
     *
     * @param body response body
     * @return filter result with governed content and metadata
     */
    public FilterResult processResponse(String body) {
        GovernanceResult result = governResponse(body);
        return new FilterResult(result.getOutput(), result, false);
    }

    /**
     * Create HTTP headers map for governance metadata.
     *
     * @param result governance result
     * @return map of header names to values
     */
    public java.util.Map<String, String> createHeaders(GovernanceResult result) {
        java.util.Map<String, String> headers = new java.util.HashMap<>();
        headers.put("X-Tork-Receipt-Id", result.getReceipt().getReceiptId());
        headers.put("X-Tork-Action", result.getAction().getCode());
        if (result.hasPII()) {
            headers.put("X-Tork-PII-Detected", "true");
            headers.put("X-Tork-PII-Types",
                String.join(",", result.getPiiTypes().stream()
                    .map(t -> t.getCode())
                    .toArray(String[]::new)));
        }
        return headers;
    }
}
