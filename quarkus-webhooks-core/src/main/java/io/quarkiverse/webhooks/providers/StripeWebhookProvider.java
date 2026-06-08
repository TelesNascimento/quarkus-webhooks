package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class StripeWebhookProvider implements WebhookProvider {

    private static final String HEADER_NAME = "stripe-signature";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int DEFAULT_REPLAY_WINDOW_SECONDS = 300;

    private final int replayWindowSeconds;

    public StripeWebhookProvider() {
        this(DEFAULT_REPLAY_WINDOW_SECONDS);
    }

    public StripeWebhookProvider(int replayWindowSeconds) {
        this.replayWindowSeconds = replayWindowSeconds;
    }

    @Override
    public String name() {
        return "stripe";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        String signatureHeader = findHeader(headers, HEADER_NAME);
        if (signatureHeader == null || signatureHeader.isBlank()) {
            throw new WebhookSignatureException("stripe", "missing Stripe-Signature header");
        }
        ParsedSignature parsed = parseSignatureHeader(signatureHeader);
        validateTimestamp(parsed.timestamp());
        String signedPayload = parsed.timestamp() + "." + new String(rawBody, StandardCharsets.UTF_8);
        byte[] expected = computeHmac(signedPayload.getBytes(StandardCharsets.UTF_8), secret);
        for (String sig : parsed.signatures()) {
            byte[] received = hexToBytes(sig);
            if (received != null && MessageDigest.isEqual(expected, received)) {
                return;
            }
        }
        throw new WebhookSignatureException("stripe", "no matching v1= signature found");
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            return extractJsonField(json, "id");
        } catch (Exception ignored) {
            return null;
        }
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

    private record ParsedSignature(String timestamp, List<String> signatures) {}

    private ParsedSignature parseSignatureHeader(String header) {
        String timestamp = null;
        List<String> signatures = new ArrayList<>();
        for (String rawPart : header.split(",")) {
            String part = rawPart.trim();
            if (part.startsWith("t=")) {
                timestamp = part.substring(2);
            } else if (part.startsWith("v1=")) {
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
            long now = Instant.now().getEpochSecond();
            if (Math.abs(now - ts) > replayWindowSeconds) {
                throw new WebhookSignatureException("stripe",
                        "timestamp too old or too far in the future (window=" + replayWindowSeconds + "s)");
            }
        } catch (NumberFormatException e) {
            throw new WebhookSignatureException("stripe", "invalid timestamp format: " + timestamp);
        }
    }

    private byte[] computeHmac(byte[] data, String secret) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new WebhookSignatureException("stripe", "HMAC computation failed: " + e.getMessage());
        }
    }

    private byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            return null;
        }
        try {
            byte[] result = new byte[hex.length() / 2];
            for (int i = 0; i < hex.length(); i += 2) {
                result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
            }
            return result;
        } catch (NumberFormatException ignored) {
            return null;
        }
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
        int start = json.indexOf('"', colon + 1);
        if (start < 0) {
            return null;
        }
        int end = json.indexOf('"', start + 1);
        if (end < 0) {
            return null;
        }
        return json.substring(start + 1, end);
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
}
