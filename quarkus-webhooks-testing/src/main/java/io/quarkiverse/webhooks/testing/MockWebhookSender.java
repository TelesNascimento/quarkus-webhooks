package io.quarkiverse.webhooks.testing;

import io.quarkiverse.webhooks.WebhookProvider;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;

/**
 * Fluent sender for signed webhook payloads in integration tests.
 *
 * <p>Can be used in two ways:</p>
 *
 * <h2>CDI injection (recommended in {@code @QuarkusTest})</h2>
 * <pre>{@code
 * @QuarkusTest
 * class PaymentTest {
 *     @Inject MockWebhookSender sender;
 *
 *     @Test
 *     void test() {
 *         sender.provider("stripe")
 *               .secret("whsec_test")
 *               .payload("{\"id\":\"evt_1\"}")
 *               .send("/webhooks/stripe")
 *               .statusCode(200);
 *     }
 * }
 * }</pre>
 *
 * <h2>Programmatic (unit tests, no CDI context)</h2>
 * <pre>{@code
 * MockWebhookSender sender = new MockWebhookSender(List.of(
 *     new StripeWebhookProvider(),
 *     new GitHubWebhookProvider()
 * ));
 * }</pre>
 *
 * <p>Providers that support {@code sign()}: Stripe, GitHub, Shopify, Slack, Standard Webhooks.
 * Adyen is excluded — it uses non-standard field-based signing.</p>
 */
@ApplicationScoped
public class MockWebhookSender {

    @Inject
    @Any
    Instance<WebhookProvider> injectedProviders;

    private final List<WebhookProvider> explicitProviders;

    /**
     * CDI no-arg constructor. Required for proxy generation.
     * When instantiated by CDI, providers are injected via {@code @Inject Instance<WebhookProvider>}.
     */
    public MockWebhookSender() {
        this.explicitProviders = null;
    }

    /**
     * Programmatic constructor for use outside a CDI context (e.g. plain unit tests).
     *
     * @param providers list of providers to use for signing
     * @throws IllegalArgumentException if providers is null
     */
    public MockWebhookSender(List<WebhookProvider> providers) {
        if (providers == null) {
            throw new IllegalArgumentException("providers must not be null");
        }
        this.explicitProviders = new ArrayList<>(providers);
    }

    /**
     * Starts building a signed request for the given provider name.
     *
     * @param name provider name (e.g. "stripe", "github", "slack")
     * @return builder to configure and send the request
     * @throws IllegalArgumentException if no provider with that name is registered
     */
    public ProviderBuilder provider(String name) {
        Iterable<WebhookProvider> source = explicitProviders != null ? explicitProviders : injectedProviders;
        if (source == null) {
            throw new IllegalStateException("No providers available — inject MockWebhookSender via CDI or use the programmatic constructor");
        }
        for (WebhookProvider p : source) {
            if (p.name().equals(name)) {
                return new ProviderBuilder(p);
            }
        }
        throw new IllegalArgumentException("Unknown provider: '" + name + "'. Check that the provider is registered.");
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
         * Adds a custom header (merged with signed headers; custom headers take precedence on conflict).
         */
        public ProviderBuilder header(String name, String value) {
            this.extraHeaders.put(name, value);
            return this;
        }

        /**
         * Sends the signed webhook to the given path using RestAssured.
         *
         * @param path HTTP path (e.g. "/webhooks/stripe")
         * @return RestAssured {@link ValidatableResponse} for assertion chaining
         * @throws IllegalStateException         if secret or payload is not set
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
