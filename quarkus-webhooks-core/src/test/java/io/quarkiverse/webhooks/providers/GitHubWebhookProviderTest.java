package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("GitHubWebhookProvider")
class GitHubWebhookProviderTest extends WebhookProviderContractTest {

    private static final String SECRET = "test_github_secret_for_tests";

    @Override
    protected WebhookProvider createProvider() {
        return new GitHubWebhookProvider();
    }

    @Override
    protected byte[] validBody() {
        return "{\"action\":\"opened\",\"issue\":{\"number\":42}}".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected Map<String, String> validHeaders() {
        byte[] body = validBody();
        byte[] hmac = WebhookProviderUtils.computeHmac(body, SECRET, "github");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        return Map.of(
                "X-Hub-Signature-256", "sha256=" + hexHmac,
                "X-GitHub-Delivery", "12345678-1234-1234-1234-123456789012",
                "X-GitHub-Event", "issues"
        );
    }

    @Override
    protected String validSecret() {
        return SECRET;
    }

    @Override
    protected String expectedProviderName() {
        return "github";
    }

    @Test
    @DisplayName("verify() — missing sha256= prefix → WebhookSignatureException")
    void verify_missingPrefix_throws() {
        byte[] body = validBody();
        byte[] hmac = WebhookProviderUtils.computeHmac(body, SECRET, "github");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        Map<String, String> headers = Map.of("X-Hub-Signature-256", hexHmac);
        assertThatThrownBy(() -> provider.verify(body, headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class);
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
    @DisplayName("verify() — header case insensitive (lowercase)")
    void verify_headerCaseInsensitive() {
        byte[] body = validBody();
        byte[] hmac = WebhookProviderUtils.computeHmac(body, SECRET, "github");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        Map<String, String> headers = Map.of(
                "x-hub-signature-256", "sha256=" + hexHmac
        );
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("extractEventId() — returns X-GitHub-Delivery header")
    void extractEventId_returnsDeliveryHeader() {
        String deliveryId = "abc-123-uuid";
        Map<String, String> headers = Map.of("X-GitHub-Delivery", deliveryId);
        assertThat(provider.extractEventId(validBody(), headers)).isEqualTo(deliveryId);
    }

    @Test
    @DisplayName("extractEventType() — returns X-GitHub-Event header")
    void extractEventType_returnsEventHeader() {
        Map<String, String> headers = Map.of("X-GitHub-Event", "push");
        assertThat(provider.extractEventType(validBody(), headers)).isEqualTo("push");
    }

    @Test
    @DisplayName("sign() — produces headers that verify correctly")
    void sign_roundtrip() {
        byte[] body = validBody();
        Map<String, String> headers = provider.sign(body, SECRET);
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("sign() — returns Map with X-Hub-Signature-256 starting with sha256=")
    void sign_headerFormat() {
        Map<String, String> headers = provider.sign(validBody(), SECRET);
        assertThat(headers).containsKey("X-Hub-Signature-256");
        assertThat(headers.get("X-Hub-Signature-256")).startsWith("sha256=");
    }
}
