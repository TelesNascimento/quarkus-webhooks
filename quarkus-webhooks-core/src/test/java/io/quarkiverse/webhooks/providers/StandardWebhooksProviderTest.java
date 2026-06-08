package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("StandardWebhooksProvider")
class StandardWebhooksProviderTest {

    // Base64-encoded 32-byte key
    private static final String SECRET_BASE64 = Base64.getEncoder()
            .encodeToString("test-secret-key-for-standard-wh".getBytes(StandardCharsets.UTF_8));
    private static final String SECRET_WITH_PREFIX = "whsec_" + SECRET_BASE64;

    private StandardWebhooksProvider provider;

    @BeforeEach
    void setUp() {
        provider = new StandardWebhooksProvider();
    }

    // --- HAPPY PATH ---

    @Test
    @DisplayName("valid signature — does not throw")
    void validSignature_doesNotThrow() throws Exception {
        byte[] body = "{\"type\":\"user.created\",\"data\":{\"id\":\"usr_001\"}}".getBytes();
        String id = "msg_abc123";
        long ts = Instant.now().getEpochSecond();
        String sig = computeSignature(id, ts, body, SECRET_BASE64);

        Map<String, String> headers = Map.of(
                "webhook-id", id,
                "webhook-timestamp", String.valueOf(ts),
                "webhook-signature", "v1," + sig
        );
        assertThatCode(() -> provider.verify(body, headers, SECRET_BASE64)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("secret with whsec_ prefix — stripped and verified correctly")
    void secretWithPrefix_strippedCorrectly() throws Exception {
        byte[] body = "{}".getBytes();
        String id = "msg_prefix";
        long ts = Instant.now().getEpochSecond();
        String sig = computeSignature(id, ts, body, SECRET_BASE64);

        Map<String, String> headers = Map.of(
                "webhook-id", id,
                "webhook-timestamp", String.valueOf(ts),
                "webhook-signature", "v1," + sig
        );
        // Secret has whsec_ prefix — should be stripped before use
        assertThatCode(() -> provider.verify(body, headers, SECRET_WITH_PREFIX)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("multiple v1 signatures — any valid passes")
    void multipleSignatures_anyValidPasses() throws Exception {
        byte[] body = "{}".getBytes();
        String id = "msg_multi";
        long ts = Instant.now().getEpochSecond();
        String validSig = computeSignature(id, ts, body, SECRET_BASE64);

        Map<String, String> headers = Map.of(
                "webhook-id", id,
                "webhook-timestamp", String.valueOf(ts),
                "webhook-signature", "v1,invalidsig== v1," + validSig
        );
        assertThatCode(() -> provider.verify(body, headers, SECRET_BASE64)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("case-insensitive headers")
    void caseInsensitiveHeaders() throws Exception {
        byte[] body = "{}".getBytes();
        String id = "msg_case";
        long ts = Instant.now().getEpochSecond();
        String sig = computeSignature(id, ts, body, SECRET_BASE64);

        Map<String, String> headers = Map.of(
                "Webhook-ID", id,
                "Webhook-Timestamp", String.valueOf(ts),
                "Webhook-Signature", "v1," + sig
        );
        assertThatCode(() -> provider.verify(body, headers, SECRET_BASE64)).doesNotThrowAnyException();
    }

    // --- INVALID ---

    @Test
    @DisplayName("wrong secret — throws")
    void wrongSecret_throws() throws Exception {
        byte[] body = "{}".getBytes();
        String id = "msg_wrong";
        long ts = Instant.now().getEpochSecond();
        String sig = computeSignature(id, ts, body, SECRET_BASE64);
        String wrongSecret = Base64.getEncoder().encodeToString("wrong-secret-key-32-bytes-here!!".getBytes());

        Map<String, String> headers = Map.of(
                "webhook-id", id, "webhook-timestamp", String.valueOf(ts),
                "webhook-signature", "v1," + sig);
        assertThatThrownBy(() -> provider.verify(body, headers, wrongSecret))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("missing webhook-id — throws")
    void missingId_throws() {
        long ts = Instant.now().getEpochSecond();
        Map<String, String> headers = Map.of("webhook-timestamp", String.valueOf(ts), "webhook-signature", "v1,abc");
        assertThatThrownBy(() -> provider.verify("{}".getBytes(), headers, SECRET_BASE64))
                .isInstanceOf(WebhookSignatureException.class).hasMessageContaining("webhook-id");
    }

    @Test
    @DisplayName("missing webhook-timestamp — throws")
    void missingTimestamp_throws() {
        Map<String, String> headers = Map.of("webhook-id", "msg_001", "webhook-signature", "v1,abc");
        assertThatThrownBy(() -> provider.verify("{}".getBytes(), headers, SECRET_BASE64))
                .isInstanceOf(WebhookSignatureException.class).hasMessageContaining("webhook-timestamp");
    }

    @Test
    @DisplayName("missing webhook-signature — throws")
    void missingSignature_throws() {
        long ts = Instant.now().getEpochSecond();
        Map<String, String> headers = Map.of("webhook-id", "msg_001", "webhook-timestamp", String.valueOf(ts));
        assertThatThrownBy(() -> provider.verify("{}".getBytes(), headers, SECRET_BASE64))
                .isInstanceOf(WebhookSignatureException.class).hasMessageContaining("webhook-signature");
    }

    @Test
    @DisplayName("expired timestamp — throws")
    void expiredTimestamp_throws() throws Exception {
        byte[] body = "{}".getBytes();
        String id = "msg_old";
        long old = Instant.now().getEpochSecond() - 600;
        String sig = computeSignature(id, old, body, SECRET_BASE64);
        Map<String, String> headers = Map.of(
                "webhook-id", id, "webhook-timestamp", String.valueOf(old), "webhook-signature", "v1," + sig);
        assertThatThrownBy(() -> provider.verify(body, headers, SECRET_BASE64))
                .isInstanceOf(WebhookSignatureException.class).hasMessageContaining("timestamp too old");
    }

    @Test
    @DisplayName("invalid Base64 secret — throws")
    void invalidSecret_throws() {
        long ts = Instant.now().getEpochSecond();
        Map<String, String> headers = Map.of(
                "webhook-id", "id", "webhook-timestamp", String.valueOf(ts), "webhook-signature", "v1,abc");
        assertThatThrownBy(() -> provider.verify("{}".getBytes(), headers, "not-base64!!!"))
                .isInstanceOf(WebhookSignatureException.class).hasMessageContaining("Base64");
    }

    // --- METADATA ---

    @Test
    @DisplayName("extractEventId returns webhook-id header")
    void extractEventId_returnsWebhookId() {
        Map<String, String> headers = Map.of("webhook-id", "msg_event_001");
        assertThat(provider.extractEventId("{}".getBytes(), headers)).isEqualTo("msg_event_001");
    }

    @Test
    @DisplayName("extractEventType parses type from JSON body")
    void extractEventType_parsesFromBody() {
        byte[] body = "{\"type\":\"order.completed\",\"data\":{}}".getBytes();
        assertThat(provider.extractEventType(body, Map.of())).isEqualTo("order.completed");
    }

    @Test
    @DisplayName("name() returns 'standard'")
    void name_returnsStandard() {
        assertThat(provider.name()).isEqualTo("standard");
    }

    // --- HELPER ---

    private String computeSignature(String id, long timestamp, byte[] body, String secretBase64) throws Exception {
        byte[] key = Base64.getDecoder().decode(secretBase64);
        String signed = id + "." + timestamp + "." + new String(body, StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
    }
}
