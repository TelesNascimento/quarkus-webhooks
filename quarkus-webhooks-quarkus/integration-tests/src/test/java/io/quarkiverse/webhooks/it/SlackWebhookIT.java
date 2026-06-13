package io.quarkiverse.webhooks.it;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static io.restassured.RestAssured.given;

@QuarkusTest
@DisplayName("Slack Webhook - Integration Tests")
class SlackWebhookIT {

    private static final String SLACK_SECRET = "test_slack_secret_for_integration_tests";

    @Test
    @DisplayName("Slack - valid signature and current timestamp - route passes")
    void slack_validSignature_notRejected() throws Exception {
        String body = "{\"type\":\"event_callback\",\"event\":{\"type\":\"message\"}}";
        long ts = Instant.now().getEpochSecond();
        String sig = computeSlackSignature(ts, body, SLACK_SECRET);

        given()
                .contentType("application/json")
                .header("X-Slack-Signature", "v0=" + sig)
                .header("X-Slack-Request-Timestamp", String.valueOf(ts))
                .body(body)
                .when()
                .post("/webhooks/slack")
                .then()
                .statusCode(404);
    }

    @Test
    @DisplayName("Slack - invalid signature - 401")
    void slack_invalidSignature_returns401() {
        given()
                .contentType("application/json")
                .header("X-Slack-Signature", "v0=0000000000000000000000000000000000000000000000000000000000000000")
                .header("X-Slack-Request-Timestamp", String.valueOf(Instant.now().getEpochSecond()))
                .body("{}")
                .when()
                .post("/webhooks/slack")
                .then()
                .statusCode(401);
    }

    @Test
    @DisplayName("Slack - expired timestamp - 401")
    void slack_expiredTimestamp_returns401() throws Exception {
        String body = "{}";
        long oldTs = Instant.now().getEpochSecond() - 360;
        String sig = computeSlackSignature(oldTs, body, SLACK_SECRET);

        given()
                .contentType("application/json")
                .header("X-Slack-Signature", "v0=" + sig)
                .header("X-Slack-Request-Timestamp", String.valueOf(oldTs))
                .body(body)
                .when()
                .post("/webhooks/slack")
                .then()
                .statusCode(401);
    }

    @Test
    @DisplayName("Slack - missing signature header - 401")
    void slack_missingSignature_returns401() {
        given()
                .contentType("application/json")
                .header("X-Slack-Request-Timestamp", String.valueOf(Instant.now().getEpochSecond()))
                .body("{}")
                .when()
                .post("/webhooks/slack")
                .then()
                .statusCode(401);
    }

    private String computeSlackSignature(long ts, String body, String secret) throws Exception {
        String signedContent = "v0:" + ts + ":" + body;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hmac = mac.doFinal(signedContent.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hmac) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
