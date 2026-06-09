package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class SlackWebhookProvider implements WebhookProvider {

    private static final String HEADER_SIGNATURE = "X-Slack-Signature";
    private static final String HEADER_TIMESTAMP = "X-Slack-Request-Timestamp";
    private static final String SIGNATURE_PREFIX = "v0=";
    private static final String SIGNED_CONTENT_PREFIX = "v0";
    private static final int DEFAULT_REPLAY_WINDOW_SECONDS = 300;
    private static final int MIN_REPLAY_WINDOW_SECONDS = 60;
    private static final int MAX_REPLAY_WINDOW_SECONDS = 3600;

    private final int replayWindowSeconds;

    public SlackWebhookProvider() {
        this(DEFAULT_REPLAY_WINDOW_SECONDS);
    }

    public SlackWebhookProvider(int replayWindowSeconds) {
        if (replayWindowSeconds < MIN_REPLAY_WINDOW_SECONDS || replayWindowSeconds > MAX_REPLAY_WINDOW_SECONDS) {
            throw new IllegalArgumentException(
                    "replayWindowSeconds must be between " + MIN_REPLAY_WINDOW_SECONDS
                            + " and " + MAX_REPLAY_WINDOW_SECONDS);
        }
        this.replayWindowSeconds = replayWindowSeconds;
    }

    @Override
    public String name() {
        return "slack";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        if (rawBody == null) {
            throw new WebhookSignatureException("slack", "missing request body");
        }
        String signatureHeader = WebhookProviderUtils.findHeader(headers, HEADER_SIGNATURE);
        String timestampHeader = WebhookProviderUtils.findHeader(headers, HEADER_TIMESTAMP);
        if (signatureHeader == null || signatureHeader.isBlank()) {
            throw new WebhookSignatureException("slack", "missing X-Slack-Signature header");
        }
        if (timestampHeader == null || timestampHeader.isBlank()) {
            throw new WebhookSignatureException("slack", "missing X-Slack-Request-Timestamp header");
        }
        validateTimestamp(timestampHeader);
        if (!signatureHeader.startsWith(SIGNATURE_PREFIX)) {
            throw new WebhookSignatureException("slack",
                    "invalid signature format - expected v0= prefix");
        }
        String receivedHex = signatureHeader.substring(SIGNATURE_PREFIX.length());
        String body = new String(rawBody, StandardCharsets.UTF_8);
        String signedContent = SIGNED_CONTENT_PREFIX + ":" + timestampHeader + ":" + body;
        byte[] expected = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), secret, "slack");
        byte[] received = WebhookProviderUtils.hexToBytesSafe(receivedHex);
        if (!MessageDigest.isEqual(expected, received)) {
            throw new WebhookSignatureException("slack", "signature mismatch");
        }
    }

    @Override
    public Map<String, String> sign(byte[] rawBody, String secret) {
        long ts = Instant.now().getEpochSecond();
        String body = new String(rawBody, StandardCharsets.UTF_8);
        String signedContent = SIGNED_CONTENT_PREFIX + ":" + ts + ":" + body;
        byte[] hmac = WebhookProviderUtils.computeHmac(
                signedContent.getBytes(StandardCharsets.UTF_8), secret, "slack");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        Map<String, String> headers = new HashMap<>();
        headers.put(HEADER_SIGNATURE, SIGNATURE_PREFIX + hexHmac);
        headers.put(HEADER_TIMESTAMP, String.valueOf(ts));
        return headers;
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            String eventId = WebhookProviderUtils.extractJsonField(json, "event_id");
            if (eventId != null) {
                return eventId;
            }
            return extractNestedEventField(json, "event_id");
        } catch (Exception ignored) {
            return null;
        }
    }

    @Override
    public String extractEventType(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            String topType = WebhookProviderUtils.extractJsonField(json, "type");
            if ("event_callback".equals(topType)) {
                String nestedType = extractNestedEventField(json, "type");
                if (nestedType != null) {
                    return nestedType;
                }
            }
            return topType;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String extractNestedEventField(String json, String fieldName) {
        String eventBlock = extractEventBlock(json);
        if (eventBlock == null) {
            return null;
        }
        return WebhookProviderUtils.extractJsonField(eventBlock, fieldName);
    }

    private String extractEventBlock(String json) {
        int eventIdx = json.indexOf("\"event\"");
        if (eventIdx < 0) {
            return null;
        }
        int braceOpen = json.indexOf('{', eventIdx + "\"event\"".length());
        if (braceOpen < 0) {
            return null;
        }
        int braceClose = findMatchingBrace(json, braceOpen);
        if (braceClose < 0) {
            return null;
        }
        return json.substring(braceOpen, braceClose + 1);
    }

    private int findMatchingBrace(String json, int braceOpen) {
        int depth = 0;
        boolean inString = false;
        for (int i = braceOpen; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) {
                inString = !inString;
            }
            if (!inString) {
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        return i;
                    }
                }
            }
        }
        return -1;
    }

    private void validateTimestamp(String timestamp) {
        try {
            long ts = Long.parseLong(timestamp);
            if (ts < 0) {
                throw new WebhookSignatureException("slack", "invalid timestamp: negative value");
            }
            long now = Instant.now().getEpochSecond();
            long diff = Math.abs(now - ts);
            if (diff > replayWindowSeconds) {
                throw new WebhookSignatureException("slack",
                        "timestamp too old or too far in the future (window=" + replayWindowSeconds + "s)");
            }
        } catch (NumberFormatException e) {
            throw new WebhookSignatureException("slack", "invalid timestamp format: " + timestamp);
        }
    }
}
