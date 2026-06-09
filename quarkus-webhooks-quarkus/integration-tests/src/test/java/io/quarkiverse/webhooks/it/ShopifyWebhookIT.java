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
@DisplayName("Shopify Webhook — Integration Tests")
class ShopifyWebhookIT {

    private static final String SHOPIFY_SECRET = "test_shopify_secret_for_integration_tests";

    @Test
    @DisplayName("Shopify — valid signature — route passes (no 401)")
    void shopify_validSignature_notRejected() throws Exception {
        byte[] body = "{\"id\":123,\"email\":\"test@example.com\"}".getBytes(StandardCharsets.UTF_8);
        String base64Hmac = shopifyHmac(body, SHOPIFY_SECRET);

        given()
                .contentType("application/json")
                .header("X-Shopify-Hmac-SHA256", base64Hmac)
                .header("X-Shopify-Topic", "orders/create")
                .header("X-Shopify-Webhook-Id", "shopify-test-001")
                .body(body)
                .when()
                .post("/webhooks/shopify")
                .then()
                .statusCode(404);
    }

    @Test
    @DisplayName("Shopify — invalid signature — 401")
    void shopify_invalidSignature_returns401() {
        given()
                .contentType("application/json")
                .header("X-Shopify-Hmac-SHA256", "aW52YWxpZHNpZ25hdHVyZQ==")
                .header("X-Shopify-Topic", "orders/create")
                .body("{}")
                .when()
                .post("/webhooks/shopify")
                .then()
                .statusCode(401);
    }

    @Test
    @DisplayName("Shopify — missing signature header — 401")
    void shopify_missingSignature_returns401() {
        given()
                .contentType("application/json")
                .header("X-Shopify-Topic", "orders/create")
                .body("{}")
                .when()
                .post("/webhooks/shopify")
                .then()
                .statusCode(401);
    }

    private String shopifyHmac(byte[] body, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(body));
    }
}
