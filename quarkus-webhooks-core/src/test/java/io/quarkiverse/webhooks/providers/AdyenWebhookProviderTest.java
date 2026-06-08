package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("AdyenWebhookProvider")
class AdyenWebhookProviderTest {

    // Real test HMAC key from Adyen docs (hex-encoded)
    private static final String HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    private AdyenWebhookProvider provider;

    @BeforeEach
    void setUp() {
        provider = new AdyenWebhookProvider();
    }

    // --- HAPPY PATH ---

    @Test
    @DisplayName("valid HMAC signature — does not throw")
    void validSignature_doesNotThrow() throws Exception {
        String notificationItem = buildNotificationItem(
                "8414369581407235", "", "TestMerchant",
                "TestPayment-001", "1000", "EUR", "AUTHORISATION", "true"
        );
        String hmac = computeAdyenHmac(HMAC_KEY_HEX, notificationItem);
        String payload = wrapInAdyenPayload(notificationItem, hmac);

        assertThatCode(() -> provider.verify(payload.getBytes(StandardCharsets.UTF_8), Map.of(), HMAC_KEY_HEX))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("extractEventId — returns pspReference")
    void extractEventId_returnsPspReference() throws Exception {
        String notificationItem = buildNotificationItem(
                "PSP-REF-9999", "", "MerchantABC", "ORDER-42", "500", "GBP", "CAPTURE", "true"
        );
        String hmac = computeAdyenHmac(HMAC_KEY_HEX, notificationItem);
        String payload = wrapInAdyenPayload(notificationItem, hmac);

        assertThat(provider.extractEventId(payload.getBytes(StandardCharsets.UTF_8), Map.of()))
                .isEqualTo("PSP-REF-9999");
    }

    @Test
    @DisplayName("extractEventType — returns eventCode")
    void extractEventType_returnsEventCode() throws Exception {
        String notificationItem = buildNotificationItem(
                "PSP-123", "", "MerchantXYZ", "REF-001", "100", "USD", "REFUND", "true"
        );
        String hmac = computeAdyenHmac(HMAC_KEY_HEX, notificationItem);
        String payload = wrapInAdyenPayload(notificationItem, hmac);

        assertThat(provider.extractEventType(payload.getBytes(StandardCharsets.UTF_8), Map.of()))
                .isEqualTo("REFUND");
    }

    // --- INVALID SIGNATURE ---

    @Test
    @DisplayName("wrong HMAC — throws WebhookSignatureException")
    void wrongHmac_throwsException() {
        String notificationItem = buildNotificationItem(
                "PSP-001", "", "Merchant", "Ref", "100", "EUR", "AUTHORISATION", "true"
        );
        String wrongHmac = "aGVsbG8gd29ybGQ="; // "hello world" base64
        String payload = wrapInAdyenPayload(notificationItem, wrongHmac);

        assertThatThrownBy(() -> provider.verify(payload.getBytes(StandardCharsets.UTF_8), Map.of(), HMAC_KEY_HEX))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("adyen");
    }

    @Test
    @DisplayName("wrong key — throws WebhookSignatureException")
    void wrongKey_throwsException() throws Exception {
        String notificationItem = buildNotificationItem(
                "PSP-002", "", "Merchant", "Ref", "100", "EUR", "AUTHORISATION", "true"
        );
        String hmac = computeAdyenHmac(HMAC_KEY_HEX, notificationItem);
        String payload = wrapInAdyenPayload(notificationItem, hmac);
        String wrongKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assertThatThrownBy(() -> provider.verify(payload.getBytes(StandardCharsets.UTF_8), Map.of(), wrongKey))
                .isInstanceOf(WebhookSignatureException.class);
    }

    @Test
    @DisplayName("invalid hex key — throws WebhookSignatureException")
    void invalidHexKey_throwsException() throws Exception {
        String notificationItem = buildNotificationItem(
                "PSP-003", "", "Merchant", "Ref", "100", "EUR", "AUTHORISATION", "true"
        );
        String hmac = computeAdyenHmac(HMAC_KEY_HEX, notificationItem);
        String payload = wrapInAdyenPayload(notificationItem, hmac);

        assertThatThrownBy(() -> provider.verify(payload.getBytes(StandardCharsets.UTF_8), Map.of(), "not-hex!"))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("invalid HMAC key");
    }

    @Test
    @DisplayName("missing hmacSignature in additionalData — throws WebhookSignatureException")
    void missingHmacField_throwsException() {
        String payload = """
                {"notificationItems":[{"NotificationRequestItem":{
                    "pspReference":"PSP-999",
                    "eventCode":"AUTHORISATION",
                    "success":"true",
                    "additionalData":{}
                }}]}""";

        assertThatThrownBy(() -> provider.verify(payload.getBytes(StandardCharsets.UTF_8), Map.of(), HMAC_KEY_HEX))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("missing hmacSignature");
    }

    @Test
    @DisplayName("no NotificationRequestItem — throws WebhookSignatureException")
    void noNotificationItem_throwsException() {
        String payload = "{\"notificationItems\":[]}";
        assertThatThrownBy(() -> provider.verify(payload.getBytes(StandardCharsets.UTF_8), Map.of(), HMAC_KEY_HEX))
                .isInstanceOf(WebhookSignatureException.class)
                .hasMessageContaining("no NotificationRequestItem");
    }

    // --- DATA-TO-SIGN ---

    @Test
    @DisplayName("buildDataToSign — joins fields in exact order with ':'")
    void buildDataToSign_correctFieldOrder() {
        String item = buildNotificationItem(
                "psp1", "origRef1", "merchant1", "ref1", "500", "EUR", "AUTHORISATION", "true"
        );
        String dataToSign = provider.buildDataToSign(item);
        assertThat(dataToSign).isEqualTo("psp1:origRef1:merchant1:ref1:500:EUR:AUTHORISATION:true");
    }

    @Test
    @DisplayName("buildDataToSign — empty originalReference is empty string not null")
    void buildDataToSign_emptyOriginalReference() {
        String item = buildNotificationItem(
                "psp2", "", "merchant2", "ref2", "100", "GBP", "CAPTURE", "true"
        );
        String dataToSign = provider.buildDataToSign(item);
        assertThat(dataToSign).startsWith("psp2::merchant2:");
    }

    @Test
    @DisplayName("name() — returns 'adyen'")
    void name_returnsAdyen() {
        assertThat(provider.name()).isEqualTo("adyen");
    }

    // --- HELPERS ---

    private String buildNotificationItem(String pspRef, String origRef, String merchantCode,
                                          String merchantRef, String amountValue, String currency,
                                          String eventCode, String success) {
        return String.format("""
            {
              "pspReference": "%s",
              "originalReference": "%s",
              "merchantAccountCode": "%s",
              "merchantReference": "%s",
              "amount": {"value": %s, "currency": "%s"},
              "eventCode": "%s",
              "success": "%s"
            }""", pspRef, origRef, merchantCode, merchantRef, amountValue, currency, eventCode, success);
    }

    private String computeAdyenHmac(String hmacKeyHex, String notificationItemJson) throws Exception {
        // Build data-to-sign using the provider's own method
        String dataToSign = provider.buildDataToSign(notificationItemJson);

        // Decode hex key
        byte[] keyBytes = new byte[hmacKeyHex.length() / 2];
        for (int i = 0; i < hmacKeyHex.length(); i += 2) {
            keyBytes[i / 2] = (byte) Integer.parseInt(hmacKeyHex.substring(i, i + 2), 16);
        }

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
        byte[] hmac = mac.doFinal(dataToSign.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmac);
    }

    private String wrapInAdyenPayload(String notificationItemJson, String hmacSignature) {
        // Inject hmacSignature into additionalData
        String itemWithHmac = notificationItemJson.replace(
                "\"success\":",
                "\"additionalData\": {\"hmacSignature\": \"" + hmacSignature + "\"}, \"success\":"
        );
        return "{\"notificationItems\":[{\"NotificationRequestItem\":" + itemWithHmac + "}]}";
    }
}
