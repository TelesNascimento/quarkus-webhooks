package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public class StandardWebhooksProvider implements WebhookProvider {

    private static final String HEADER_ID = "webhook-id";
    private static final String HEADER_TIMESTAMP = "webhook-timestamp";
    private static final String HEADER_SIGNATURE = "webhook-signature";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int DEFAULT_REPLAY_WINDOW_SECONDS = 300;
    private static final String SECRET_PREFIX = "whsec_";

    private final int replayWindowSeconds;

    public StandardWebhooksProvider() {
        this(DEFAULT_REPLAY_WINDOW_SECONDS);
    }

    public StandardWebhooksProvider(int replayWindowSeconds) {
        this.replayWindowSeconds = replayWindowSeconds;
    }

    @Override
    public String name() {
        return "standard";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        String webhookId = findHeader(headers, HEADER_ID);
        String timestamp = findHeader(headers, HEADER_TIMESTAMP);
        String signatureHeader = findHeader(headers, HEADER_SIGNATURE);
        validateRequiredHeaders(webhookId, timestamp, signatureHeader);
        try {
            long ts = Long.parseLong(timestamp);
            long now = Instant.now().getEpochSecond();
            if (Math.abs(now - ts) > replayWindowSeconds) {
                throw new WebhookSignatureException("standard",
                        "timestamp too old or in the future (window=" + replayWindowSeconds + "s)");
            }
        } catch (NumberFormatException e) {
            throw new WebhookSignatureException("standard", "invalid webhook-timestamp format: " + timestamp);
        }
        byte[] keyBytes;
        try {
            String rawSecret;
            if (secret.startsWith(SECRET_PREFIX)) {
                rawSecret = secret.substring(SECRET_PREFIX.length());
            } else {
                rawSecret = secret;
            }
            keyBytes = Base64.getDecoder().decode(rawSecret);
        } catch (IllegalArgumentException e) {
            throw new WebhookSignatureException("standard", "invalid secret - must be Base64 encoded");
        }
        String body = new String(rawBody, StandardCharsets.UTF_8);
        String signedContent = webhookId + "." + timestamp + "." + body;
        byte[] expected = computeHmac(signedContent.getBytes(StandardCharsets.UTF_8), keyBytes);
        String expectedBase64 = Base64.getEncoder().encodeToString(expected);
        for (String sig : signatureHeader.split(" ")) {
            sig = sig.trim();
            if (!sig.startsWith("v1,")) {
                continue;
            }
            String candidate = sig.substring(3);
            if (MessageDigest.isEqual(
                    expectedBase64.getBytes(StandardCharsets.UTF_8),
                    candidate.getBytes(StandardCharsets.UTF_8))) {
                return;
            }
        }
        throw new WebhookSignatureException("standard", "no matching v1, signature found");
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        return findHeader(headers, HEADER_ID);
    }

    @Override
    public String extractEventType(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            return extractJsonField(json, "type");
        } catch (Exception ignored) {
            return null;
        }
    }

    private byte[] computeHmac(byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new WebhookSignatureException("standard", "HMAC computation failed: " + e.getMessage());
        }
    }

    private void validateRequiredHeaders(String webhookId, String timestamp, String signatureHeader) {
        if (webhookId == null || webhookId.isBlank()) {
            throw new WebhookSignatureException("standard", "missing webhook-id header");
        }
        if (timestamp == null || timestamp.isBlank()) {
            throw new WebhookSignatureException("standard", "missing webhook-timestamp header");
        }
        if (signatureHeader == null || signatureHeader.isBlank()) {
            throw new WebhookSignatureException("standard", "missing webhook-signature header");
        }
    }

    private String findHeader(Map<String, String> headers, String name) {
        if (headers == null) {
            return null;
        }
        return headers.entrySet().stream()
                .filter(entry -> name.equalsIgnoreCase(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }

    private String extractJsonField(String json, String field) {
        String key = "\"" + field + "\"";
        int idx = json.indexOf(key);
        if (idx < 0) {
            return null;
        }
        int colon = json.indexOf(':', idx + key.length());
        if (colon < 0) {
            return null;
        }
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        if (start >= json.length()) {
            return null;
        }
        if (json.charAt(start) == '"') {
            int end = json.indexOf('"', start + 1);
            if (end < 0) {
                return null;
            }
            return json.substring(start + 1, end);
        }
        int end = start;
        while (end < json.length() && ",}]".indexOf(json.charAt(end)) < 0) {
            end++;
        }
        return json.substring(start, end).trim();
    }
}
