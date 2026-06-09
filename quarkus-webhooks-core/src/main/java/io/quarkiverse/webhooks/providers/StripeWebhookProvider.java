package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class StripeWebhookProvider implements WebhookProvider {

    private static final String HEADER_NAME = "stripe-signature";
    private static final int DEFAULT_REPLAY_WINDOW_SECONDS = 300;
    private static final int MIN_REPLAY_WINDOW_SECONDS = 60;
    private static final int MAX_REPLAY_WINDOW_SECONDS = 3600;
    private static final int MAX_SIGNATURES = 10;

    private final int replayWindowSeconds;

    public StripeWebhookProvider() {
        this(DEFAULT_REPLAY_WINDOW_SECONDS);
    }

    public StripeWebhookProvider(int replayWindowSeconds) {
        if (replayWindowSeconds < MIN_REPLAY_WINDOW_SECONDS || replayWindowSeconds > MAX_REPLAY_WINDOW_SECONDS) {
            throw new IllegalArgumentException(
                    "replayWindowSeconds must be between " + MIN_REPLAY_WINDOW_SECONDS
                            + " and " + MAX_REPLAY_WINDOW_SECONDS);
        }
        this.replayWindowSeconds = replayWindowSeconds;
    }

    @Override
    public String name() {
        return "stripe";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        String signatureHeader = WebhookProviderUtils.findHeader(headers, HEADER_NAME);
        if (signatureHeader == null || signatureHeader.isBlank()) {
            throw new WebhookSignatureException("stripe", "missing Stripe-Signature header");
        }
        ParsedSignature parsed = parseSignatureHeader(signatureHeader);
        validateTimestamp(parsed.timestamp());
        String signedPayload = parsed.timestamp() + "." + new String(rawBody, StandardCharsets.UTF_8);
        byte[] expected = WebhookProviderUtils.computeHmac(
                signedPayload.getBytes(StandardCharsets.UTF_8), secret, "stripe");
        for (String sig : parsed.signatures()) {
            byte[] received = WebhookProviderUtils.hexToBytesSafe(sig);
            if (MessageDigest.isEqual(expected, received)) {
                return;
            }
        }
        throw new WebhookSignatureException("stripe", "no matching v1= signature found");
    }

    @Override
    public Map<String, String> sign(byte[] rawBody, String secret) {
        long ts = Instant.now().getEpochSecond();
        String signedPayload = ts + "." + new String(rawBody, StandardCharsets.UTF_8);
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedPayload.getBytes(StandardCharsets.UTF_8), secret, "stripe");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        return Map.of(HEADER_NAME, "t=" + ts + ",v1=" + hexHmac);
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            return WebhookProviderUtils.extractJsonField(json, "id");
        } catch (Exception ignored) {
            return null;
        }
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

    private record ParsedSignature(String timestamp, List<String> signatures) {}

    private ParsedSignature parseSignatureHeader(String header) {
        String timestamp = null;
        List<String> signatures = new ArrayList<>();
        for (String rawPart : header.split(",")) {
            String part = rawPart.trim();
            if (part.startsWith("t=")) {
                timestamp = part.substring(2);
            } else if (part.startsWith("v1=") && signatures.size() < MAX_SIGNATURES) {
                signatures.add(part.substring(3));
            }
        }
        if (timestamp == null) {
            throw new WebhookSignatureException("stripe", "missing timestamp (t=) in Stripe-Signature");
        }
        if (signatures.isEmpty()) {
            throw new WebhookSignatureException("stripe", "no v1= signatures found in Stripe-Signature");
        }
        return new ParsedSignature(timestamp, signatures);
    }

    private void validateTimestamp(String timestamp) {
        try {
            long ts = Long.parseLong(timestamp);
            if (ts < 0) {
                throw new WebhookSignatureException("stripe", "invalid timestamp: negative value");
            }
            long now = Instant.now().getEpochSecond();
            long diff = Math.abs(now - ts);
            if (diff > replayWindowSeconds) {
                throw new WebhookSignatureException("stripe",
                        "timestamp too old or too far in the future (window=" + replayWindowSeconds + "s)");
            }
        } catch (NumberFormatException e) {
            throw new WebhookSignatureException("stripe", "invalid timestamp format: " + timestamp);
        }
    }
}
