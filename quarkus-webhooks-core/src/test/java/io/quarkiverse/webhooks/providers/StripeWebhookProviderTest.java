package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

@DisplayName("StripeWebhookProvider")
class StripeWebhookProviderTest {

    private static final String SECRET = "whsec_test_secret_for_tests";
    private StripeWebhookProvider provider;

    @BeforeEach
    void setUp() {
        provider = new StripeWebhookProvider();
    }

    @Test
    @DisplayName("valid signature - does not throw")
    void validSignature_doesNotThrow() throws Exception {
        byte[] body = "{\"id\":\"evt_123\",\"type\":\"payment_intent.succeeded\"}".getBytes(StandardCharsets.UTF_8);
        long timestamp = Instant.now().getEpochSecond();
        String sig = computeStripeSignature(timestamp, body, SECRET);
        Map<String, String> headers = Map.of(
                "stripe-signature", "t=" + timestamp + ",v1=" + sig
        );
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("multiple v1= signatures - any one valid is sufficient")
    void multipleSignatures_anyValidSuffices() throws Exception {
        byte[] body = "{\"id\":\"evt_456\"}".getBytes(StandardCharsets.UTF_8);
        long timestamp = Instant.now().getEpochSecond();
        String validSig = computeStripeSignature(timestamp, body, SECRET);
        Map<String, String> headers = Map.of(
                "stripe-signature", "t=" + timestamp + ",v1=invalidsig000,v1=" + validSig
        );
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("case-insensitive header name - Stripe-Signature vs stripe-signature")
    void headerLookup_caseInsensitive() throws Exception {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        long timestamp = Instant.now().getEpochSecond();
        String sig = computeStripeSignature(timestamp, body, SECRET);

        Map<String, String> headers = Map.of(
                "Stripe-Signature", "t=" + timestamp + ",v1=" + sig
        );
        assertThatCode(() -> provider.verify(body, headers, SECRET)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("invalid signature - throws WebhookSignatureException")
    void invalidSignature_throwsException() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        long timestamp = Instant.now().getEpochSecond();
        Map<String, String> headers = Map.of(
                "stripe-signature", "t=" + timestamp + ",v1=deadbeefdeadbeef"
        );
        assertThatThrownBy(() -> provider.verify(body, headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("stripe");
    }

    @Test
    @DisplayName("wrong secret - throws WebhookSignatureException")
    void wrongSecret_throwsException() throws Exception {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        long timestamp = Instant.now().getEpochSecond();
        String sig = computeStripeSignature(timestamp, body, "correct-secret");
        Map<String, String> headers = Map.of(
                "stripe-signature", "t=" + timestamp + ",v1=" + sig
        );
        assertThatThrownBy(() -> provider.verify(body, headers, "wrong-secret"))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("missing header - throws WebhookSignatureException")
    void missingHeader_throwsException() {
        assertThatThrownBy(() ->
                provider.verify("{}".getBytes(), Map.of(), SECRET)
        ).isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("missing Stripe-Signature header");
    }

    @Test
    @DisplayName("missing timestamp (t=) - throws WebhookSignatureException")
    void missingTimestamp_throwsException() {
        Map<String, String> headers = Map.of("stripe-signature", "v1=abc123");
        assertThatThrownBy(() -> provider.verify("{}".getBytes(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("missing timestamp");
    }

    @Test
    @DisplayName("no v1= signatures - throws WebhookSignatureException")
    void noV1Signatures_throwsException() {
        Map<String, String> headers = Map.of(
                "stripe-signature", "t=" + Instant.now().getEpochSecond()
        );
        assertThatThrownBy(() -> provider.verify("{}".getBytes(), headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("no v1= signatures");
    }

    @Test
    @DisplayName("expired timestamp - throws WebhookSignatureException")
    void expiredTimestamp_throwsException() throws Exception {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        long oldTimestamp = Instant.now().getEpochSecond() - 600;
        String sig = computeStripeSignature(oldTimestamp, body, SECRET);
        Map<String, String> headers = Map.of(
                "stripe-signature", "t=" + oldTimestamp + ",v1=" + sig
        );
        assertThatThrownBy(() -> provider.verify(body, headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("timestamp too old");
    }

    @Test
    @DisplayName("custom replay window - accepts within window, rejects outside")
    void customReplayWindow_enforcesWindow() throws Exception {

        StripeWebhookProvider strictProvider = new StripeWebhookProvider(60);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        long oldTimestamp = Instant.now().getEpochSecond() - 70;
        String sig = computeStripeSignature(oldTimestamp, body, SECRET);
        Map<String, String> headers = Map.of(
                "stripe-signature", "t=" + oldTimestamp + ",v1=" + sig
        );
        assertThatThrownBy(() -> strictProvider.verify(body, headers, SECRET))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("extractEventId - returns id from JSON body")
    void extractEventId_returnsId() {
        byte[] body = "{\"id\":\"evt_001\",\"type\":\"charge.succeeded\"}".getBytes(StandardCharsets.UTF_8);
        assertThat(provider.extractEventId(body, Map.of())).isEqualTo("evt_001");
    }

    @Test
    @DisplayName("extractEventType - returns type from JSON body")
    void extractEventType_returnsType() {
        byte[] body = "{\"id\":\"evt_001\",\"type\":\"charge.succeeded\"}".getBytes(StandardCharsets.UTF_8);
        assertThat(provider.extractEventType(body, Map.of())).isEqualTo("charge.succeeded");
    }

    @Test
    @DisplayName("extractEventId - returns null for empty body")
    void extractEventId_emptyBody_returnsNull() {
        assertThat(provider.extractEventId("{}".getBytes(), Map.of())).isNull();
    }

    @Test
    @DisplayName("name() - returns 'stripe'")
    void name_returnsStripe() {
        assertThat(provider.name()).isEqualTo("stripe");
    }

    private String computeStripeSignature(long timestamp, byte[] body, String secret) throws Exception {
        String signedPayload = timestamp + "." + new String(body, StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(signedPayload.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
