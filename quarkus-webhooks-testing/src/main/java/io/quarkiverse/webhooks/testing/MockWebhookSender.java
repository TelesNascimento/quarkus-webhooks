package io.quarkiverse.webhooks.testing;

import io.quarkiverse.webhooks.WebhookProvider;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;

/**
 * Fluent sender for signed webhook payloads in integration tests.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * MockWebhookSender sender = new MockWebhookSender(providers);
 * sender.provider("stripe")
 *       .secret("whsec_test")
 *       .payload("{\"id\":\"evt_1\"}")
 *       .send("/webhooks/stripe")
 *       .statusCode(200);
 * }</pre>
 *
 * <p>In a {@code @QuarkusTest}, instantiate with all available providers:</p>
 * <pre>{@code
 * @Inject Instance<WebhookProvider> providers;
 * MockWebhookSender sender = new MockWebhookSender(providers.stream().collect(Collectors.toList()));
 * }</pre>
 */
public class MockWebhookSender {

    private final List<WebhookProvider> providers;

    public MockWebhookSender(List<WebhookProvider> providers) {
        if (providers == null) {
            throw new IllegalArgumentException("providers must not be null");
        }
        this.providers = providers;
    }

    /**
     * Starts building a signed request for the given provider name.
     *
     * @param name provider name (e.g. "stripe", "github", "slack")
     * @return builder to configure and send the request
     * @throws IllegalArgumentException if no provider with that name is registered
     */
    public ProviderBuilder provider(String name) {
        for (WebhookProvider p : providers) {
            if (p.name().equals(name)) {
                return new ProviderBuilder(p);
            }
        }
        throw new IllegalArgumentException(
                "Unknown provider: '" + name + "'. Available: " + providerNames());
    }

    private String providerNames() {
        StringBuilder sb = new StringBuilder();
        for (WebhookProvider p : providers) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(p.name());
        }
        return sb.toString();
    }

    /**
     * Builder for a single signed webhook request.
     */
    public static final class ProviderBuilder {

        private final WebhookProvider provider;
        private String secret;
        private byte[] rawBody;
        private final Map<String, String> extraHeaders = new HashMap<>();

        private ProviderBuilder(WebhookProvider provider) {
            this.provider = provider;
        }

        /**
         * Sets the signing secret.
         */
        public ProviderBuilder secret(String secret) {
            this.secret = secret;
            return this;
        }

        /**
         * Sets the request body as a JSON string.
         */
        public ProviderBuilder payload(String json) {
            this.rawBody = json.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        /**
         * Adds a custom header to the request (merged with signed headers).
         * Custom headers override signed headers on conflict.
         */
        public ProviderBuilder header(String name, String value) {
            this.extraHeaders.put(name, value);
            return this;
        }

        /**
         * Sends the signed webhook to the given path using RestAssured.
         *
         * <p>The body is signed using {@link WebhookProvider#sign(byte[], String)}.
         * Headers from {@code sign()} are merged with any {@link #header(String, String)} overrides.</p>
         *
         * @param path HTTP path (e.g. "/webhooks/stripe")
         * @return RestAssured {@code ValidatableResponse} for assertion chaining
         * @throws IllegalStateException     if secret or payload is not set
         * @throws UnsupportedOperationException if the provider does not support signing
         */
        public ValidatableResponse send(String path) {
            if (secret == null) {
                throw new IllegalStateException("secret must be set before calling send()");
            }
            if (rawBody == null) {
                throw new IllegalStateException("payload must be set before calling send()");
            }
            Map<String, String> signedHeaders = provider.sign(rawBody, secret);
            Map<String, String> allHeaders = new HashMap<>(signedHeaders);
            allHeaders.putAll(extraHeaders);

            RequestSpecification request = given()
                    .contentType("application/json")
                    .body(rawBody);

            for (Map.Entry<String, String> entry : allHeaders.entrySet()) {
                request = request.header(entry.getKey(), entry.getValue());
            }

            return request.when().post(path).then();
        }
    }
}
