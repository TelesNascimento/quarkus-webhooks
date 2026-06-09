package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

public class ShopifyWebhookProvider implements WebhookProvider {

    private static final String HEADER_HMAC = "X-Shopify-Hmac-SHA256";
    private static final String HEADER_WEBHOOK_ID = "X-Shopify-Webhook-Id";
    private static final String HEADER_TOPIC = "X-Shopify-Topic";
    private static final int MAX_HMAC_HEADER_LENGTH = 100;

    @Override
    public String name() {
        return "shopify";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        if (rawBody == null) {
            throw new WebhookSignatureException("shopify", "missing request body");
        }
        String hmacHeader = WebhookProviderUtils.findHeader(headers, HEADER_HMAC);
        if (hmacHeader == null || hmacHeader.isBlank()) {
            throw new WebhookSignatureException("shopify", "missing X-Shopify-Hmac-SHA256 header");
        }
        if (hmacHeader.length() > MAX_HMAC_HEADER_LENGTH) {
            throw new WebhookSignatureException("shopify",
                    "X-Shopify-Hmac-SHA256 header exceeds maximum length");
        }
        byte[] expected = WebhookProviderUtils.computeHmac(rawBody, secret, "shopify");
        String expectedBase64 = Base64.getEncoder().encodeToString(expected).replaceAll("=+$", "");
        String receivedBase64 = hmacHeader.replaceAll("=+$", "");
        if (!MessageDigest.isEqual(
                expectedBase64.getBytes(StandardCharsets.UTF_8),
                receivedBase64.getBytes(StandardCharsets.UTF_8))) {
            throw new WebhookSignatureException("shopify", "HMAC signature mismatch");
        }
    }

    @Override
    public Map<String, String> sign(byte[] rawBody, String secret) {
        byte[] hmac = WebhookProviderUtils.computeHmac(rawBody, secret, "shopify");
        String base64Hmac = Base64.getEncoder().encodeToString(hmac);
        return Map.of(HEADER_HMAC, base64Hmac);
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        return WebhookProviderUtils.findHeader(headers, HEADER_WEBHOOK_ID);
    }

    @Override
    public String extractEventType(byte[] rawBody, Map<String, String> headers) {
        return WebhookProviderUtils.findHeader(headers, HEADER_TOPIC);
    }
}
