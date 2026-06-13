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

@QuarkusTest
@DisplayName("Standard Webhooks Integration Tests")
class StandardWebhooksIT {

    // Base64-encoded key matching application.properties
    private static final String SECRET = "dGVzdC1zZWNyZXQta2V5LWZvci1zdGFuZGFyZC13aA==";

    @Test
    @DisplayName("POST /webhooks/standard - valid signature - passes (not 401)")
    void standard_validSignature_passes() throws Exception {
        String id = "msg_test_001";
        long ts = Instant.now().getEpochSecond();
        String body = "{\"type\":\"user.created\"}";
        String sig = computeSignature(id, ts, body);

        given()
            .contentType("application/json")
            .header("webhook-id", id)
            .header("webhook-timestamp", String.valueOf(ts))
            .header("webhook-signature", "v1," + sig)
            .body(body)
        .when()
            .post("/webhooks/standard")
        .then()
            .statusCode(404); // valid -> passed through
    }

    @Test
    @DisplayName("POST /webhooks/standard - invalid signature - 401")
    void standard_invalidSignature_returns401() {
        long ts = Instant.now().getEpochSecond();
        given()
            .contentType("application/json")
            .header("webhook-id", "msg_bad")
            .header("webhook-timestamp", String.valueOf(ts))
            .header("webhook-signature", "v1,badsignature==")
            .body("{}")
        .when()
            .post("/webhooks/standard")
        .then()
            .statusCode(401);
    }

    private String computeSignature(String id, long ts, String body) throws Exception {
        byte[] key = Base64.getDecoder().decode(SECRET);
        String signed = id + "." + ts + "." + body;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.getEncoder().encodeToString(
            mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
    }
}
