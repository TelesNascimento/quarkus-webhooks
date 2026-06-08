package io.quarkiverse.webhooks.it;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static io.restassured.RestAssured.given;

@QuarkusTest
@DisplayName("Adyen Webhook Integration Tests")
class AdyenWebhookIT {

    private static final String HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    @Test
    @DisplayName("POST /webhooks/adyen — valid HMAC — passes (not 401)")
    void adyen_validHmac_passes() throws Exception {
        String notificationItem = buildItem("PSP-001", "", "MerchantTest", "OrderRef", "1000", "EUR", "AUTHORISATION", "true");
        String hmac = computeAdyenHmac(notificationItem);
        String payload = wrapPayload(notificationItem, hmac);

        given()
            .contentType("application/json")
            .body(payload)
        .when()
            .post("/webhooks/adyen")
        .then()
            .statusCode(404); // valid signature → passed through, no downstream endpoint
    }

    @Test
    @DisplayName("POST /webhooks/adyen — wrong HMAC — 401")
    void adyen_wrongHmac_returns401() {
        String notificationItem = buildItem("PSP-002", "", "MerchantTest", "OrderRef", "1000", "EUR", "AUTHORISATION", "true");
        String payload = wrapPayload(notificationItem, "aGVsbG8gd29ybGQ="); // wrong hmac

        given()
            .contentType("application/json")
            .body(payload)
        .when()
            .post("/webhooks/adyen")
        .then()
            .statusCode(401);
    }

    private String buildItem(String psp, String orig, String merchant, String ref,
                              String val, String cur, String event, String success) {
        return String.format("{\"pspReference\":\"%s\",\"originalReference\":\"%s\","
            + "\"merchantAccountCode\":\"%s\",\"merchantReference\":\"%s\","
            + "\"amount\":{\"value\":%s,\"currency\":\"%s\"},"
            + "\"eventCode\":\"%s\",\"success\":\"%s\"}",
            psp, orig, merchant, ref, val, cur, event, success);
    }

    private String computeAdyenHmac(String item) throws Exception {
        // Fields in exact order
        String[] parts = {
            extract(item, "pspReference"), extract(item, "originalReference"),
            extract(item, "merchantAccountCode"), extract(item, "merchantReference"),
            extractAmount(item, "value"), extractAmount(item, "currency"),
            extract(item, "eventCode"), extract(item, "success")
        };
        String dataToSign = String.join(":", parts);
        byte[] key = new byte[HMAC_KEY_HEX.length() / 2];
        for (int i = 0; i < HMAC_KEY_HEX.length(); i += 2)
            key[i/2] = (byte) Integer.parseInt(HMAC_KEY_HEX.substring(i, i+2), 16);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(dataToSign.getBytes(StandardCharsets.UTF_8)));
    }

    private String wrapPayload(String item, String hmac) {
        String withHmac = item.replace("\"success\":",
            "\"additionalData\":{\"hmacSignature\":\"" + hmac + "\"},\"success\":");
        return "{\"notificationItems\":[{\"NotificationRequestItem\":" + withHmac + "}]}";
    }

    private String extract(String json, String field) {
        String k = "\"" + field + "\"";
        int i = json.indexOf(k); if (i < 0) return "";
        int c = json.indexOf(':', i + k.length()); if (c < 0) return "";
        int s = c + 1;
        while (s < json.length() && Character.isWhitespace(json.charAt(s))) s++;
        if (s >= json.length()) return "";
        if (json.charAt(s) == '"') {
            // string value
            int e = json.indexOf('"', s + 1);
            return e < 0 ? "" : json.substring(s + 1, e);
        } else {
            // numeric or boolean value
            int e = s;
            while (e < json.length() && ",}]".indexOf(json.charAt(e)) < 0) e++;
            return json.substring(s, e).trim();
        }
    }

    private String extractAmount(String json, String sub) {
        int ai = json.indexOf("\"amount\""); if (ai < 0) return "";
        int bo = json.indexOf('{', ai); if (bo < 0) return "";
        int bc = json.indexOf('}', bo); if (bc < 0) return "";
        return extract(json.substring(bo, bc+1), sub);
    }
}
