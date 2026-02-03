package com.tork.governance.middleware;

import com.tork.governance.GovernanceResult;
import com.tork.governance.Tork;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Spring Boot HandlerInterceptor for Tork governance.
 *
 * <p>Alternative to filter-based governance, operates at the Spring MVC level.</p>
 *
 * <h2>Usage with Spring Boot:</h2>
 * <pre>{@code
 * @Configuration
 * public class WebConfig implements WebMvcConfigurer {
 *     @Override
 *     public void addInterceptors(InterceptorRegistry registry) {
 *         registry.addInterceptor(new SpringBootInterceptor())
 *                 .addPathPatterns("/api/**")
 *                 .excludePathPatterns("/api/health");
 *     }
 * }
 * }</pre>
 */
public class SpringBootInterceptor {
    private final Tork tork;

    /**
     * Create interceptor with default Tork instance.
     */
    public SpringBootInterceptor() {
        this.tork = new Tork();
    }

    /**
     * Create interceptor with API key.
     * @param apiKey the API key
     */
    public SpringBootInterceptor(String apiKey) {
        this.tork = new Tork(apiKey);
    }

    /**
     * Create interceptor with custom Tork instance.
     * @param tork the Tork instance
     */
    public SpringBootInterceptor(Tork tork) {
        this.tork = tork;
    }

    /**
     * Pre-handle hook for request governance.
     * Note: This is a simplified version - actual Spring HandlerInterceptor
     * implementation would extend HandlerInterceptorAdapter.
     */
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {

        String method = request.getMethod();

        // Only process requests with body
        if (!hasRequestBody(method)) {
            return true;
        }

        // Get the governed result if filter already processed it
        GovernanceResult result = (GovernanceResult) request.getAttribute("torkResult");

        if (result != null && result.isDenied()) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"error\":\"Request blocked by governance policy\"," +
                "\"receiptId\":\"" + result.getReceipt().getReceiptId() + "\"}"
            );
            return false;
        }

        return true;
    }

    /**
     * Post-handle hook for response governance.
     */
    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                           Object handler, Object modelAndView) {
        // Response governance would be handled here if needed
    }

    /**
     * After completion hook.
     */
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        // Cleanup if needed
    }

    private boolean hasRequestBody(String method) {
        return "POST".equalsIgnoreCase(method) ||
               "PUT".equalsIgnoreCase(method) ||
               "PATCH".equalsIgnoreCase(method);
    }

    /**
     * Get the Tork instance used by this interceptor.
     * @return the Tork instance
     */
    public Tork getTork() {
        return tork;
    }

    /**
     * Govern text directly using this interceptor's Tork instance.
     * @param text the text to govern
     * @return governance result
     */
    public GovernanceResult govern(String text) {
        return tork.govern(text);
    }
}
