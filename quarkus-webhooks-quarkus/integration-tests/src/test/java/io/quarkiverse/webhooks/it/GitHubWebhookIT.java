package io.quarkiverse.webhooks.it;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static io.restassured.RestAssured.given;

@QuarkusTest
@DisplayName("GitHub Webhook — Integration Tests")
class GitHubWebhookIT {

    private static final String GITHUB_SECRET = "test_github_secret_for_integration_tests";

    @Test
    @DisplayName("GitHub — valid signature — route passes (no 401)")
    void github_validSignature_notRejected() throws Exception {
        byte[] body = "{\"action\":\"opened\",\"issue\":{\"number\":1}}".getBytes(StandardCharsets.UTF_8);
        String hexHmac = githubHmac(body, GITHUB_SECRET);

        given()
                .contentType("application/json")
                .header("X-Hub-Signature-256", "sha256=" + hexHmac)
                .header("X-GitHub-Event", "issues")
                .header("X-GitHub-Delivery", "test-delivery-001")
                .body(body)
                .when()
                .post("/webhooks/github")
                .then()
                .statusCode(404);
    }

    @Test
    @DisplayName("GitHub — invalid signature — 401")
    void github_invalidSignature_returns401() {
        given()
                .contentType("application/json")
                .header("X-Hub-Signature-256", "sha256=0000000000000000000000000000000000000000000000000000000000000000")
                .header("X-GitHub-Event", "push")
                .body("{}")
                .when()
                .post("/webhooks/github")
                .then()
                .statusCode(401);
    }

    @Test
    @DisplayName("GitHub — missing signature header — 401")
    void github_missingSignature_returns401() {
        given()
                .contentType("application/json")
                .header("X-GitHub-Event", "push")
                .body("{}")
                .when()
                .post("/webhooks/github")
                .then()
                .statusCode(401);
    }

    private String githubHmac(byte[] body, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(body);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
