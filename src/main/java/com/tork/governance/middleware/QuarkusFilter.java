package com.tork.governance.middleware;

import com.tork.governance.GovernanceResult;
import com.tork.governance.Tork;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Quarkus JAX-RS Filter for Tork governance.
 *
 * <p>Implements ContainerRequestFilter and ContainerResponseFilter for
 * governing both request and response content.</p>
 *
 * <h2>Usage with Quarkus:</h2>
 * <pre>{@code
 * // Register automatically via @Provider annotation
 * // Or register manually in Application class:
 *
 * @ApplicationPath("/api")
 * public class MyApplication extends Application {
 *     @Override
 *     public Set<Class<?>> getClasses() {
 *         Set<Class<?>> classes = new HashSet<>();
 *         classes.add(QuarkusFilter.class);
 *         // ... other resources
 *         return classes;
 *     }
 * }
 * }</pre>
 *
 * <h2>Accessing governance result in resource:</h2>
 * <pre>{@code
 * @Path("/chat")
 * public class ChatResource {
 *     @POST
 *     public Response chat(@Context ContainerRequestContext ctx, String body) {
 *         GovernanceResult result = (GovernanceResult) ctx.getProperty("torkResult");
 *         // Use governed content
 *     }
 * }
 * }</pre>
 */
@Provider
public class QuarkusFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private final Tork tork;
    private boolean governResponse = true;

    /**
     * Create filter with default Tork instance.
     */
    public QuarkusFilter() {
        this.tork = new Tork();
    }

    /**
     * Create filter with API key.
     * @param apiKey the API key
     */
    public QuarkusFilter(String apiKey) {
        this.tork = new Tork(apiKey);
    }

    /**
     * Create filter with custom Tork instance.
     * @param tork the Tork instance
     */
    public QuarkusFilter(Tork tork) {
        this.tork = tork;
    }

    /**
     * Set whether to govern response content.
     * @param governResponse true to govern responses
     * @return this filter for chaining
     */
    public QuarkusFilter setGovernResponse(boolean governResponse) {
        this.governResponse = governResponse;
        return this;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String method = requestContext.getMethod();

        // Only process requests with body
        if (!hasRequestBody(method)) {
            return;
        }

        // Read and govern request body
        InputStream inputStream = requestContext.getEntityStream();
        String originalBody = readInputStream(inputStream);

        if (originalBody.isEmpty()) {
            return;
        }

        GovernanceResult result = tork.govern(originalBody);

        // Store result for access in resource
        requestContext.setProperty("torkResult", result);
        requestContext.setProperty("torkReceiptId", result.getReceipt().getReceiptId());

        // Check if request should be blocked
        if (result.isDenied()) {
            requestContext.abortWith(
                Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"error\":\"Request blocked by governance policy\"," +
                           "\"receiptId\":\"" + result.getReceipt().getReceiptId() + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build()
            );
            return;
        }

        // Replace entity stream with governed content
        byte[] governedBytes = result.getOutput().getBytes(StandardCharsets.UTF_8);
        requestContext.setEntityStream(new ByteArrayInputStream(governedBytes));
    }

    @Override
    public void filter(ContainerRequestContext requestContext,
                       ContainerResponseContext responseContext) throws IOException {

        if (!governResponse) {
            return;
        }

        Object entity = responseContext.getEntity();
        if (entity instanceof String) {
            GovernanceResult result = tork.govern((String) entity);
            responseContext.setEntity(result.getOutput());

            // Add governance headers
            responseContext.getHeaders().add("X-Tork-Receipt-Id",
                result.getReceipt().getReceiptId());
            if (result.hasPII()) {
                responseContext.getHeaders().add("X-Tork-PII-Detected", "true");
            }
        }
    }

    private boolean hasRequestBody(String method) {
        return "POST".equalsIgnoreCase(method) ||
               "PUT".equalsIgnoreCase(method) ||
               "PATCH".equalsIgnoreCase(method);
    }

    private String readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = inputStream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString(StandardCharsets.UTF_8.name());
    }

    /**
     * Get the Tork instance used by this filter.
     * @return the Tork instance
     */
    public Tork getTork() {
        return tork;
    }
}
