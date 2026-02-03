package com.tork.governance.middleware;

import com.tork.governance.GovernanceResult;
import com.tork.governance.Tork;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * Spring Boot Servlet Filter for Tork governance.
 *
 * <p>Automatically governs request body content, detecting and redacting PII.</p>
 *
 * <h2>Usage with Spring Boot:</h2>
 * <pre>{@code
 * @Configuration
 * public class FilterConfig {
 *     @Bean
 *     public FilterRegistrationBean<SpringBootFilter> torkFilter() {
 *         FilterRegistrationBean<SpringBootFilter> registration = new FilterRegistrationBean<>();
 *         registration.setFilter(new SpringBootFilter());
 *         registration.addUrlPatterns("/api/*");
 *         registration.setOrder(1);
 *         return registration;
 *     }
 * }
 * }</pre>
 *
 * <h2>Accessing governance result in controller:</h2>
 * <pre>{@code
 * @PostMapping("/chat")
 * public ResponseEntity<?> chat(HttpServletRequest request, @RequestBody ChatRequest body) {
 *     GovernanceResult result = (GovernanceResult) request.getAttribute("torkResult");
 *     // Use governed content
 * }
 * }</pre>
 */
public class SpringBootFilter implements Filter {
    private final Tork tork;
    private String[] protectedPaths = {"/api/"};
    private String[] excludedPaths = {"/health", "/metrics"};

    /**
     * Create filter with default Tork instance.
     */
    public SpringBootFilter() {
        this.tork = new Tork();
    }

    /**
     * Create filter with API key.
     * @param apiKey the API key
     */
    public SpringBootFilter(String apiKey) {
        this.tork = new Tork(apiKey);
    }

    /**
     * Create filter with custom Tork instance.
     * @param tork the Tork instance to use
     */
    public SpringBootFilter(Tork tork) {
        this.tork = tork;
    }

    /**
     * Set paths that should be governed.
     * @param paths array of path prefixes
     * @return this filter for chaining
     */
    public SpringBootFilter setProtectedPaths(String... paths) {
        this.protectedPaths = paths;
        return this;
    }

    /**
     * Set paths that should be excluded from governance.
     * @param paths array of path prefixes
     * @return this filter for chaining
     */
    public SpringBootFilter setExcludedPaths(String... paths) {
        this.excludedPaths = paths;
        return this;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String path = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();

        // Check if path should be excluded
        for (String excluded : excludedPaths) {
            if (path.startsWith(excluded)) {
                chain.doFilter(request, response);
                return;
            }
        }

        // Check if path should be protected
        boolean shouldGovern = false;
        for (String protected_ : protectedPaths) {
            if (path.startsWith(protected_)) {
                shouldGovern = true;
                break;
            }
        }

        // Only govern POST, PUT, PATCH requests with body
        if (!shouldGovern || !hasRequestBody(method)) {
            chain.doFilter(request, response);
            return;
        }

        // Wrap request to govern body
        TorkRequestWrapper wrappedRequest = new TorkRequestWrapper(httpRequest, tork);
        GovernanceResult result = wrappedRequest.getTorkResult();

        // Store result for access in controller
        request.setAttribute("torkResult", result);
        request.setAttribute("torkReceiptId", result.getReceipt().getReceiptId());

        // Check if request should be blocked
        if (result.isDenied()) {
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"error\":\"Request blocked by governance policy\"," +
                "\"receiptId\":\"" + result.getReceipt().getReceiptId() + "\"}"
            );
            return;
        }

        chain.doFilter(wrappedRequest, response);
    }

    private boolean hasRequestBody(String method) {
        return "POST".equalsIgnoreCase(method) ||
               "PUT".equalsIgnoreCase(method) ||
               "PATCH".equalsIgnoreCase(method);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Optional initialization
    }

    @Override
    public void destroy() {
        // Optional cleanup
    }

    /**
     * Request wrapper that governs body content.
     */
    public static class TorkRequestWrapper extends HttpServletRequestWrapper {
        private final byte[] governedBody;
        private final GovernanceResult torkResult;

        public TorkRequestWrapper(HttpServletRequest request, Tork tork) throws IOException {
            super(request);

            // Read original body
            String originalBody = request.getReader().lines()
                .collect(Collectors.joining(System.lineSeparator()));

            // Govern content
            this.torkResult = tork.govern(originalBody);
            this.governedBody = torkResult.getOutput().getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            return new TorkServletInputStream(governedBody);
        }

        @Override
        public BufferedReader getReader() throws IOException {
            return new BufferedReader(
                new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }

        @Override
        public int getContentLength() {
            return governedBody.length;
        }

        @Override
        public long getContentLengthLong() {
            return governedBody.length;
        }

        public GovernanceResult getTorkResult() {
            return torkResult;
        }
    }

    /**
     * Custom ServletInputStream for governed content.
     */
    private static class TorkServletInputStream extends ServletInputStream {
        private final ByteArrayInputStream inputStream;

        public TorkServletInputStream(byte[] data) {
            this.inputStream = new ByteArrayInputStream(data);
        }

        @Override
        public int read() throws IOException {
            return inputStream.read();
        }

        @Override
        public boolean isFinished() {
            return inputStream.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            // Not implemented for synchronous reading
        }
    }
}
