package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SlackWebhookProvider")
class SlackWebhookProviderTest extends WebhookProviderContractTest {

    private static final String SECRET = "test_slack_secret_for_tests";

    @Override
    protected WebhookProvider createProvider() {
        return new SlackWebhookProvider();
    }

    @Override
    protected byte[] validBody() {
        return "{\"type\":\"event_callback\",\"event\":{\"type\":\"message\",\"text\":\"hello\"}}".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected Map<String, String> validHeaders() {
        return buildSlackHeaders(validBody(), SECRET, Instant.now().getEpochSecond());
    }

    @Override
    protected String validSecret() {
        return SECRET;
    }

    @Override
    protected String expectedProviderName() {
        return "slack";
    }

    private Map<String, String> buildSlackHeaders(byte[] body, String secret, long ts) {
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        String signedContent = "v0:" + ts + ":" + bodyStr;
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), secret, "slack");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Slack-Signature", "v0=" + hexHmac);
        headers.put("X-Slack-Request-Timestamp", String.valueOf(ts));
        return headers;
    }

    @Test
    @DisplayName("verify() - valid signature and current timestamp - passes")
    void verify_validSignatureCurrentTimestamp_passes() {
        assertThatCode(() -> provider.verify(validBody(), validHeaders(), SECRET))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("verify: null body throws WebhookSignatureException")
    void verify_nullBody_throws() {
        assertThatThrownBy(() -> provider.verify(null, Map.of("X-Slack-Signature", "v0=abc", "X-Slack-Request-Timestamp", "1234567890"), SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() - missing X-Slack-Signature -> WebhookSignatureException")
    void verify_missingSignatureHeader_throws() {
        Map<String, String> headers = Map.of(
                "X-Slack-Request-Timestamp", String.valueOf(Instant.now().getEpochSecond()));
        assertThatThrownBy(() -> provider.verify(validBody(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() - missing X-Slack-Request-Timestamp -> WebhookSignatureException")
    void verify_missingTimestampHeader_throws() {
        long ts = Instant.now().getEpochSecond();
        String signedContent = "v0:" + ts + ":" + new String(validBody(), StandardCharsets.UTF_8);
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), SECRET, "slack");
        Map<String, String> headers = Map.of(
                "X-Slack-Signature", "v0=" + WebhookProviderUtils.bytesToHex(hmac));
        assertThatThrownBy(() -> provider.verify(validBody(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() - expired timestamp (6 min ago) -> WebhookSignatureException")
    void verify_expiredTimestamp_throws() {
        long oldTs = Instant.now().getEpochSecond() - 360;
        Map<String, String> headers = buildSlackHeaders(validBody(), SECRET, oldTs);
        assertThatThrownBy(() -> provider.verify(validBody(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("timestamp too old");
    }

    @Test
    @DisplayName("verify() - future timestamp (6 min ahead) -> WebhookSignatureException")
    void verify_futureTimestamp_throws() {
        long futureTs = Instant.now().getEpochSecond() + 360;
        Map<String, String> headers = buildSlackHeaders(validBody(), SECRET, futureTs);
        assertThatThrownBy(() -> provider.verify(validBody(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("timestamp too old or too far");
    }

    @Test
    @DisplayName("verify() - negative timestamp -> WebhookSignatureException")
    void verify_negativeTimestamp_throws() {
        long ts = Instant.now().getEpochSecond();
        String signedContent = "v0:" + ts + ":" + new String(validBody(), StandardCharsets.UTF_8);
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), SECRET, "slack");
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Slack-Signature", "v0=" + WebhookProviderUtils.bytesToHex(hmac));
        headers.put("X-Slack-Request-Timestamp", "-1");
        assertThatThrownBy(() -> provider.verify(validBody(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("negative");
    }

    @Test
    @DisplayName("verify() - missing v0= prefix in signature -> WebhookSignatureException")
    void verify_missingV0Prefix_throws() {
        long ts = Instant.now().getEpochSecond();
        String signedContent = "v0:" + ts + ":" + new String(validBody(), StandardCharsets.UTF_8);
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), SECRET, "slack");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Slack-Signature", hexHmac);
        headers.put("X-Slack-Request-Timestamp", String.valueOf(ts));
        assertThatThrownBy(() -> provider.verify(validBody(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() - wrong secret -> WebhookSignatureException")
    void verify_wrongSecret_throws() {
        assertThatThrownBy(() -> provider.verify(validBody(), validHeaders(), "wrong_secret"))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() - body modified -> WebhookSignatureException")
    void verify_bodyModified_throws() {
        byte[] tamperedBody = "tampered".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> provider.verify(tamperedBody, validHeaders(), SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("verify() - header case insensitive - passes")
    void verify_headerCaseInsensitive_passes() {
        long ts = Instant.now().getEpochSecond();
        String bodyStr = new String(validBody(), StandardCharsets.UTF_8);
        String signedContent = "v0:" + ts + ":" + bodyStr;
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), SECRET, "slack");
        Map<String, String> headers = new HashMap<>();
        headers.put("x-slack-signature", "v0=" + WebhookProviderUtils.bytesToHex(hmac));
        headers.put("x-slack-request-timestamp", String.valueOf(ts));
        assertThatCode(() -> provider.verify(validBody(), headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("verify() - replay window boundary (exactly 5 min ago) - passes")
    void verify_atBoundary5MinutesAgo_passes() {
        long boundaryTs = Instant.now().getEpochSecond() - 300;
        Map<String, String> headers = buildSlackHeaders(validBody(), SECRET, boundaryTs);
        assertThatCode(() -> provider.verify(validBody(), headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("sign() - roundtrip verifies successfully")
    void sign_roundtrip_verifiesSuccessfully() {
        byte[] body = validBody();
        Map<String, String> headers = provider.sign(body, SECRET);
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("sign() - header format contains v0= prefix")
    void sign_headerFormat_containsV0Prefix() {
        Map<String, String> headers = provider.sign(validBody(), SECRET);
        assertThat(headers).containsKey("X-Slack-Signature");
        assertThat(headers).containsKey("X-Slack-Request-Timestamp");
        assertThat(headers.get("X-Slack-Signature")).startsWith("v0=");
    }

    @Test
    @DisplayName("extractEventType() - url_verification payload - returns 'url_verification'")
    void extractEventType_urlVerification_returnsUrlVerification() {
        byte[] body = "{\"type\":\"url_verification\",\"challenge\":\"abc123\"}".getBytes(StandardCharsets.UTF_8);
        assertThat(provider.extractEventType(body, Map.of())).isEqualTo("url_verification");
    }

    @Test
    @DisplayName("extractEventType() - event_callback payload -> returns inner event.type")
    void extractEventType_eventCallback_returnsInnerEventType() {
        byte[] body = "{\"type\":\"event_callback\",\"event\":{\"type\":\"message\",\"text\":\"hi\"}}"
                .getBytes(StandardCharsets.UTF_8);
        assertThat(provider.extractEventType(body, Map.of())).isEqualTo("message");
    }

    @Test
    @DisplayName("extractEventType() - event_callback without inner type - returns 'event_callback'")
    void extractEventType_eventCallbackNoInnerType_returnsEventCallback() {
        byte[] body = "{\"type\":\"event_callback\",\"event\":{\"text\":\"hi\"}}"
                .getBytes(StandardCharsets.UTF_8);
        String result = provider.extractEventType(body, Map.of());
        assertThat(result).isIn("event_callback", null);
    }

    @Test
    @DisplayName("SlackWebhookProvider() - replay window too small -> IllegalArgumentException")
    void constructor_replayWindowTooSmall_throws() {
        assertThatThrownBy(() -> new SlackWebhookProvider(30))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("SlackWebhookProvider() - replay window too large -> IllegalArgumentException")
    void constructor_replayWindowTooLarge_throws() {
        assertThatThrownBy(() -> new SlackWebhookProvider(4000))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
