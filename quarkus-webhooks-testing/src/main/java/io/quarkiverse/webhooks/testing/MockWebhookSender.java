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

@ApplicationScoped
public class MockWebhookSender {

    @Inject
    @Any
    Instance<WebhookProvider> injectedProviders;

    private final List<WebhookProvider> explicitProviders;

    public MockWebhookSender() {
        this.explicitProviders = null;
    }

    public MockWebhookSender(List<WebhookProvider> providers) {
        if (providers == null) {
            throw new IllegalArgumentException("providers must not be null");
        }
        this.explicitProviders = new ArrayList<>(providers);
    }

    public ProviderBuilder provider(String name) {
        Iterable<WebhookProvider> source = explicitProviders != null ? explicitProviders : injectedProviders;
        if (source == null) {
            throw new IllegalStateException("No providers available - inject MockWebhookSender via CDI or use the programmatic constructor");
        }
        for (WebhookProvider p : source) {
            if (p.name().equals(name)) {
                return new ProviderBuilder(p);
            }
        }
        throw new IllegalArgumentException("Unknown provider: '" + name + "'. Check that the provider is registered.");
    }

    public static final class ProviderBuilder {

        private final WebhookProvider provider;
        private String secret;
        private byte[] rawBody;
        private final Map<String, String> extraHeaders = new HashMap<>();

        private ProviderBuilder(WebhookProvider provider) {
            this.provider = provider;
        }

        public ProviderBuilder secret(String secret) {
            this.secret = secret;
            return this;
        }

        public ProviderBuilder payload(String json) {
            this.rawBody = json.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        public ProviderBuilder header(String name, String value) {
            this.extraHeaders.put(name, value);
            return this;
        }

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
