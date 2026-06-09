package io.quarkiverse.webhooks.it;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for webhook signature verification.
 *
 * Valid signature → NOT 401 (signature passed, route handler called ctx.next())
 * Invalid signature → 401 with JSON error body
 */
@QuarkusTest
@DisplayName("Webhook Signature — Integration Tests")
class WebhookSignatureTest {

    private static final String STRIPE_SECRET = "whsec_test_secret_for_integration_tests";
    private static final String ADYEN_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    private static final String STD_SECRET_B64 = "dGVzdC1zZWNyZXQta2V5LWZvci1zdGFuZGFyZC13aA==";

    // =========================================================================
    // STRIPE
    // =========================================================================

    @Test
    @DisplayName("Stripe — valid signature — route passes (no 401)")
    void stripe_validSignature_notRejected() throws Exception {
        String body = "{\"id\":\"evt_001\",\"type\":\"payment_intent.succeeded\"}";
        long ts = Instant.now().getEpochSecond();
        String sig = stripeHmac(ts, body, STRIPE_SECRET);

        given()
            .contentType("application/json")
            .header("Stripe-Signature", "t=" + ts + ",v1=" + sig)
            .body(body)
        .when()
            .post("/webhooks/stripe")
        .then()
            .statusCode(404); // valid → no 401; 404 = no JAX-RS endpoint downstream
    }

    @Test
    @DisplayName("Stripe — invalid signature — 401")
    void stripe_invalidSignature_returns401() {
        given()
            .contentType("application/json")
            .header("Stripe-Signature", "t=" + Instant.now().getEpochSecond() + ",v1=badhex0000")
            .body("{}")
        .when()
            .post("/webhooks/stripe")
        .then()
            .statusCode(401)
            .body(containsString("webhook_signature_invalid"));
    }

    @Test
    @DisplayName("Stripe — missing header — 401")
    void stripe_missingHeader_returns401() {
        given()
            .contentType("application/json")
            .body("{}")
        .when()
            .post("/webhooks/stripe")
        .then()
            .statusCode(401);
    }

    @Test
    @DisplayName("Stripe — expired timestamp — 401")
    void stripe_expiredTimestamp_returns401() throws Exception {
        String body = "{}";
        long old = Instant.now().getEpochSecond() - 600;
        String sig = stripeHmac(old, body, STRIPE_SECRET);

        given()
            .contentType("application/json")
            .header("Stripe-Signature", "t=" + old + ",v1=" + sig)
            .body(body)
        .when()
            .post("/webhooks/stripe")
        .then()
            .statusCode(401)
            .body(containsString("webhook_signature_invalid"));
    }

    // =========================================================================
    // ADYEN
    // =========================================================================

    @Test
    @DisplayName("Adyen — valid HMAC — route passes (no 401)")
    void adyen_validHmac_notRejected() throws Exception {
        String item = adyenItem("PSP-E2E-001", "", "MerchantIT", "Ref-001", "500", "EUR", "AUTHORISATION", "true");
        String hmac = adyenHmac(item, ADYEN_KEY_HEX);
        String payload = adyenWrap(item, hmac);

        given()
            .contentType("application/json")
            .body(payload)
        .when()
            .post("/webhooks/adyen")
        .then()
            .statusCode(404); // valid → no 401
    }

    @Test
    @DisplayName("Adyen — invalid HMAC — 401")
    void adyen_invalidHmac_returns401() {
        String item = adyenItem("PSP-BAD", "", "Merchant", "Ref", "100", "EUR", "AUTHORISATION", "true");
        String payload = adyenWrap(item, "d3JvbmdzaWduYXR1cmU="); // "wrongsignature" base64

        given()
            .contentType("application/json")
            .body(payload)
        .when()
            .post("/webhooks/adyen")
        .then()
            .statusCode(401);
    }

    // =========================================================================
    // STANDARD WEBHOOKS
    // =========================================================================

    @Test
    @DisplayName("Standard — valid signature — route passes (no 401)")
    void standard_validSignature_notRejected() throws Exception {
        String id = "msg_it_001";
        long ts = Instant.now().getEpochSecond();
        String body = "{\"type\":\"order.completed\"}";
        String sig = standardHmac(id, ts, body, STD_SECRET_B64);

        given()
            .contentType("application/json")
            .header("webhook-id", id)
            .header("webhook-timestamp", String.valueOf(ts))
            .header("webhook-signature", "v1," + sig)
            .body(body)
        .when()
            .post("/webhooks/standard")
        .then()
            .statusCode(404); // valid → no 401
    }

    @Test
    @DisplayName("Standard — invalid signature — 401")
    void standard_invalidSignature_returns401() {
        long ts = Instant.now().getEpochSecond();
        given()
            .contentType("application/json")
            .header("webhook-id", "msg_bad")
            .header("webhook-timestamp", String.valueOf(ts))
            .header("webhook-signature", "v1,aW52YWxpZHNpZ25hdHVyZQ==")
            .body("{}")
        .when()
            .post("/webhooks/standard")
        .then()
            .statusCode(401);
    }

    // =========================================================================
    // UNKNOWN PROVIDER
    // =========================================================================

    @Test
    @DisplayName("Unknown provider — 404")
    void unknownProvider_returns404() {
        given()
            .contentType("application/json")
            .body("{}")
        .when()
            .post("/webhooks/nonexistent")
        .then()
            .statusCode(404)
            .body(containsString("unknown_provider"));
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private String stripeHmac(long ts, String body, String secret) throws Exception {
        String signed = ts + "." + body;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(signed.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String standardHmac(String id, long ts, String body, String secretB64) throws Exception {
        byte[] key = Base64.getDecoder().decode(secretB64);
        String signed = id + "." + ts + "." + body;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.getEncoder().encodeToString(
            mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
    }

    private String adyenItem(String psp, String orig, String merchant, String ref,
                              String val, String cur, String evt, String success) {
        return String.format(
            "{\"pspReference\":\"%s\",\"originalReference\":\"%s\","
            + "\"merchantAccountCode\":\"%s\",\"merchantReference\":\"%s\","
            + "\"amount\":{\"value\":%s,\"currency\":\"%s\"},"
            + "\"eventCode\":\"%s\",\"success\":\"%s\"}",
            psp, orig, merchant, ref, val, cur, evt, success);
    }

    private String adyenHmac(String item, String keyHex) throws Exception {
        // Fields in exact Adyen order
        String[] fields = {
            jsonStr(item, "pspReference"), jsonStr(item, "originalReference"),
            jsonStr(item, "merchantAccountCode"), jsonStr(item, "merchantReference"),
            amountField(item, "value"), amountField(item, "currency"),
            jsonStr(item, "eventCode"), jsonStr(item, "success")
        };
        String data = String.join(":", fields);
        byte[] key = new byte[keyHex.length() / 2];
        for (int i = 0; i < keyHex.length(); i += 2)
            key[i/2] = (byte) Integer.parseInt(keyHex.substring(i, i+2), 16);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.getEncoder().encodeToString(
            mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private String adyenWrap(String item, String hmac) {
        String withHmac = item.replace("\"success\":",
            "\"additionalData\":{\"hmacSignature\":\"" + hmac + "\"},\"success\":");
        return "{\"notificationItems\":[{\"NotificationRequestItem\":" + withHmac + "}]}";
    }

    private String jsonStr(String json, String field) {
        String k = "\"" + field + "\"";
        int i = json.indexOf(k); if (i < 0) return "";
        int c = json.indexOf(':', i + k.length()); if (c < 0) return "";
        int s = json.indexOf('"', c + 1); if (s < 0) return "";
        int e = json.indexOf('"', s + 1); return e < 0 ? "" : json.substring(s+1, e);
    }

    private String amountField(String json, String sub) {
        int ai = json.indexOf("\"amount\""); if (ai < 0) return "";
        int bo = json.indexOf('{', ai); if (bo < 0) return "";
        int bc = json.indexOf('}', bo); if (bc < 0) return "";
        String block = json.substring(bo, bc+1);
        // Extract the field value — handles both strings and numbers
        String key = "\"" + sub + "\"";
        int ki = block.indexOf(key); if (ki < 0) return "";
        int colon = block.indexOf(':', ki + key.length()); if (colon < 0) return "";
        int start = colon + 1;
        while (start < block.length() && Character.isWhitespace(block.charAt(start))) start++;
        if (start >= block.length()) return "";
        char first = block.charAt(start);
        if (first == '"') {
            int end = block.indexOf('"', start + 1);
            return end < 0 ? "" : block.substring(start + 1, end);
        } else {
            int end = start;
            while (end < block.length() && ",}]".indexOf(block.charAt(end)) < 0) end++;
            return block.substring(start, end).trim();
        }
    }
}
