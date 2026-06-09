package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ShopifyWebhookProvider")
class ShopifyWebhookProviderTest extends WebhookProviderContractTest {

    private static final String SECRET = "test_shopify_secret_for_tests";

    @Override
    protected WebhookProvider createProvider() {
        return new ShopifyWebhookProvider();
    }

    @Override
    protected byte[] validBody() {
        return "{\"id\":123,\"topic\":\"orders/create\"}".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected Map<String, String> validHeaders() {
        byte[] body = validBody();
        byte[] hmac = WebhookProviderUtils.computeHmac(body, SECRET, "shopify");
        String base64Hmac = Base64.getEncoder().encodeToString(hmac);
        return Map.of(
                "X-Shopify-Hmac-SHA256", base64Hmac,
                "X-Shopify-Webhook-Id", "shopify-webhook-uuid-123",
                "X-Shopify-Topic", "orders/create"
        );
    }

    @Override
    protected String validSecret() {
        return SECRET;
    }

    @Override
    protected String expectedProviderName() {
        return "shopify";
    }

    @Test
    @DisplayName("verify() — Base64 without padding also accepted")
    void verify_base64WithoutPadding_accepted() {
        byte[] body = validBody();
        byte[] hmac = WebhookProviderUtils.computeHmac(body, SECRET, "shopify");
        String base64WithPadding = Base64.getEncoder().encodeToString(hmac);
        String base64WithoutPadding = base64WithPadding.replaceAll("=+$", "");
        Map<String, String> headers = Map.of("X-Shopify-Hmac-SHA256", base64WithoutPadding);
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("verify: null body throws WebhookSignatureException")
    void verify_nullBody_throws() {
        assertThatThrownBy(() -> provider.verify(null, Map.of("X-Shopify-Hmac-SHA256", "abc"), SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() — hex signature (common mistake) → WebhookSignatureException")
    void verify_hexInsteadOfBase64_throws() {
        byte[] body = validBody();
        byte[] hmac = WebhookProviderUtils.computeHmac(body, SECRET, "shopify");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        Map<String, String> headers = Map.of("X-Shopify-Hmac-SHA256", hexHmac);
        assertThatThrownBy(() -> provider.verify(body, headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() — header length exceeds limit → WebhookSignatureException (DoS protection)")
    void verify_headerTooLong_throws() {
        Map<String, String> headers = Map.of("X-Shopify-Hmac-SHA256", "A".repeat(101));
        assertThatThrownBy(() -> provider.verify(validBody(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("exceeds maximum");
    }

    @Test
    @DisplayName("verify() — wrong secret → WebhookSignatureException")
    void verify_wrongSecret_throws() {
        assertThatThrownBy(() -> provider.verify(validBody(), validHeaders(), "wrong_secret"))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() — body modified → WebhookSignatureException")
    void verify_bodyModified_throws() {
        byte[] tamperedBody = "tampered".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> provider.verify(tamperedBody, validHeaders(), SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() — header case insensitive — passes")
    void verify_headerCaseInsensitive_passes() {
        byte[] body = validBody();
        byte[] hmac = WebhookProviderUtils.computeHmac(body, SECRET, "shopify");
        String base64Hmac = Base64.getEncoder().encodeToString(hmac);
        Map<String, String> headers = Map.of("x-shopify-hmac-sha256", base64Hmac);
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("extractEventId() — returns X-Shopify-Webhook-Id")
    void extractEventId_returnsWebhookId() {
        Map<String, String> headers = Map.of("X-Shopify-Webhook-Id", "webhook-abc-123");
        assertThat(provider.extractEventId(validBody(), headers)).isEqualTo("webhook-abc-123");
    }

    @Test
    @DisplayName("extractEventType() — returns X-Shopify-Topic")
    void extractEventType_returnsTopic() {
        Map<String, String> headers = Map.of("X-Shopify-Topic", "orders/fulfilled");
        assertThat(provider.extractEventType(validBody(), headers)).isEqualTo("orders/fulfilled");
    }

    @Test
    @DisplayName("sign() — roundtrip verifies successfully")
    void sign_roundtrip_verifiesSuccessfully() {
        byte[] body = validBody();
        Map<String, String> headers = provider.sign(body, SECRET);
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }
}
