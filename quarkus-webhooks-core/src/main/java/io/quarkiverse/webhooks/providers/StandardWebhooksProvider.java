package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class StandardWebhooksProvider implements WebhookProvider {

    private static final String HEADER_ID = "webhook-id";
    private static final String HEADER_TIMESTAMP = "webhook-timestamp";
    private static final String HEADER_SIGNATURE = "webhook-signature";
    private static final int DEFAULT_REPLAY_WINDOW_SECONDS = 300;
    private static final int MIN_REPLAY_WINDOW_SECONDS = 60;
    private static final int MAX_REPLAY_WINDOW_SECONDS = 3600;
    private static final String SECRET_PREFIX = "whsec_";

    private final int replayWindowSeconds;

    public StandardWebhooksProvider() {
        this(DEFAULT_REPLAY_WINDOW_SECONDS);
    }

    public StandardWebhooksProvider(int replayWindowSeconds) {
        if (replayWindowSeconds < MIN_REPLAY_WINDOW_SECONDS || replayWindowSeconds > MAX_REPLAY_WINDOW_SECONDS) {
            throw new IllegalArgumentException(
                    "replayWindowSeconds must be between " + MIN_REPLAY_WINDOW_SECONDS
                            + " and " + MAX_REPLAY_WINDOW_SECONDS);
        }
        this.replayWindowSeconds = replayWindowSeconds;
    }

    @Override
    public String name() {
        return "standard";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        String webhookId = WebhookProviderUtils.findHeader(headers, HEADER_ID);
        String timestamp = WebhookProviderUtils.findHeader(headers, HEADER_TIMESTAMP);
        String signatureHeader = WebhookProviderUtils.findHeader(headers, HEADER_SIGNATURE);
        validateRequiredHeaders(webhookId, timestamp, signatureHeader);
        validateTimestamp(timestamp);
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
        byte[] expected = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), keyBytes, "standard");
        String expectedBase64 = Base64.getEncoder().encodeToString(expected);
        for (String rawSig : signatureHeader.split(" ")) {
            String sig = rawSig.trim();
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
    public Map<String, String> sign(byte[] rawBody, String secret) {
        String webhookId = UUID.randomUUID().toString();
        long ts = Instant.now().getEpochSecond();
        String rawSecret;
        if (secret.startsWith(SECRET_PREFIX)) {
            rawSecret = secret.substring(SECRET_PREFIX.length());
        } else {
            rawSecret = secret;
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(rawSecret);
        } catch (IllegalArgumentException e) {
            throw new WebhookSignatureException("standard", "invalid secret: must be Base64 encoded");
        }
        String body = new String(rawBody, StandardCharsets.UTF_8);
        String signedContent = webhookId + "." + ts + "." + body;
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), keyBytes, "standard");
        String sigBase64 = Base64.getEncoder().encodeToString(hmac);
        Map<String, String> resultHeaders = new HashMap<>();
        resultHeaders.put("webhook-id", webhookId);
        resultHeaders.put("webhook-timestamp", String.valueOf(ts));
        resultHeaders.put("webhook-signature", "v1," + sigBase64);
        return resultHeaders;
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        return WebhookProviderUtils.findHeader(headers, HEADER_ID);
    }

    @Override
    public String extractEventType(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            return WebhookProviderUtils.extractJsonField(json, "type");
        } catch (Exception ignored) {
            return null;
        }
    }

    private void validateTimestamp(String timestamp) {
        try {
            long ts = Long.parseLong(timestamp);
            if (ts < 0) {
                throw new WebhookSignatureException("standard", "invalid timestamp: negative value");
            }
            long now = Instant.now().getEpochSecond();
            long diff = Math.abs(now - ts);
            if (diff > replayWindowSeconds) {
                throw new WebhookSignatureException("standard",
                        "timestamp too old or in the future (window=" + replayWindowSeconds + "s)");
            }
        } catch (NumberFormatException e) {
            throw new WebhookSignatureException("standard", "invalid webhook-timestamp format: " + timestamp);
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
}
