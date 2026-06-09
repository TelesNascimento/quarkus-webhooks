package io.quarkiverse.webhooks.testing;

import io.quarkiverse.webhooks.WebhookProvider;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class MockWebhookSender {

    private final List<WebhookProvider> providers;

    public MockWebhookSender(List<WebhookProvider> providers) {
        if (providers == null) {
            throw new IllegalArgumentException("providers must not be null");
        }
        this.providers = providers;
    }

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
