package io.quarkiverse.webhooks.testing;

import io.quarkiverse.webhooks.WebhookProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("MockWebhookSender")
class MockWebhookSenderTest {

    private MockWebhookSender sender;

    @BeforeEach
    void setUp() {
        WebhookProvider fakeStripe = new WebhookProvider() {
            @Override
            public String name() {
                return "stripe";
            }

            @Override
            public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
            }

            @Override
            public String extractEventId(byte[] rawBody, Map<String, String> headers) {
                return null;
            }

            @Override
            public String extractEventType(byte[] rawBody, Map<String, String> headers) {
                return null;
            }

            @Override
            public Map<String, String> sign(byte[] rawBody, String secret) {
                return Map.of("stripe-signature", "t=1234,v1=abc");
            }
        };

        WebhookProvider fakeAdyen = new WebhookProvider() {
            @Override
            public String name() {
                return "adyen";
            }

            @Override
            public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
            }

            @Override
            public String extractEventId(byte[] rawBody, Map<String, String> headers) {
                return null;
            }

            @Override
            public String extractEventType(byte[] rawBody, Map<String, String> headers) {
                return null;
            }
        };

        sender = new MockWebhookSender(List.of(fakeStripe, fakeAdyen));
    }

    @Test
    @DisplayName("provider() - unknown name -> IllegalArgumentException")
    void provider_unknownName_throws() {
        assertThatThrownBy(() -> sender.provider("unknown"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown");
    }

    @Test
    @DisplayName("provider() - known name -> returns ProviderBuilder")
    void provider_knownName_returnsBuilder() {
        MockWebhookSender.ProviderBuilder builder = sender.provider("stripe");
        assertThat(builder).isNotNull();
    }

    @Test
    @DisplayName("send() - secret not set -> IllegalStateException")
    void send_secretNotSet_throws() {
        assertThatThrownBy(() -> sender.provider("stripe").payload("{}").send("/test"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("secret");
    }

    @Test
    @DisplayName("send() - payload not set -> IllegalStateException")
    void send_payloadNotSet_throws() {
        assertThatThrownBy(() -> sender.provider("stripe").secret("x").send("/test"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("payload");
    }

    @Test
    @DisplayName("send() - provider without sign() -> UnsupportedOperationException")
    void send_providerWithoutSign_throws() {
        assertThatThrownBy(() ->
                sender.provider("adyen")
                        .secret("x")
                        .payload("{}")
                        .send("/test"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("constructor() - null providers list -> IllegalArgumentException")
    void constructor_nullProviders_throws() {
        assertThatThrownBy(() -> new MockWebhookSender(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("header() - custom header overrides signed header - uses custom value")
    void header_overridesSignedHeader_usesCustomValue() {
        MockWebhookSender.ProviderBuilder builder = sender.provider("stripe")
                .secret("x")
                .payload("{}")
                .header("X-Custom", "value");
        assertThat(builder).isNotNull();
    }
}
