package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

public class AdyenWebhookProvider implements WebhookProvider {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HMAC_FIELD = "hmacSignature";

    @Override
    public String name() {
        return "adyen";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        String json = new String(rawBody, StandardCharsets.UTF_8);
        String item = extractNotificationItem(json);
        if (item == null) {
            throw new WebhookSignatureException("adyen", "no NotificationRequestItem found in payload");
        }
        String receivedHmac = extractAdditionalDataField(item, HMAC_FIELD);
        if (receivedHmac == null || receivedHmac.isBlank()) {
            throw new WebhookSignatureException("adyen", "missing hmacSignature in additionalData");
        }
        String dataToSign = buildDataToSign(item);
        byte[] keyBytes = hexToBytes(secret);
        if (keyBytes == null) {
            throw new WebhookSignatureException("adyen", "invalid HMAC key - must be hex-encoded string");
        }
        byte[] computedHmac = computeHmac(dataToSign.getBytes(StandardCharsets.UTF_8), keyBytes);
        String computedBase64 = Base64.getEncoder().encodeToString(computedHmac);
        if (!MessageDigest.isEqual(
                computedBase64.getBytes(StandardCharsets.UTF_8),
                receivedHmac.getBytes(StandardCharsets.UTF_8))) {
            throw new WebhookSignatureException("adyen", "HMAC signature mismatch");
        }
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            String item = extractNotificationItem(json);
            if (item == null) {
                return null;
            }
            return extractJsonField(item, "pspReference");
        } catch (Exception ignored) {
            return null;
        }
    }

    @Override
    public String extractEventType(byte[] rawBody, Map<String, String> headers) {
        try {
            String json = new String(rawBody, StandardCharsets.UTF_8);
            String item = extractNotificationItem(json);
            if (item == null) {
                return null;
            }
            return extractJsonField(item, "eventCode");
        } catch (Exception ignored) {
            return null;
        }
    }

    String buildDataToSign(String notificationItemJson) {
        String[] fields = {
            getFieldOrEmpty(notificationItemJson, "pspReference"),
            getFieldOrEmpty(notificationItemJson, "originalReference"),
            getFieldOrEmpty(notificationItemJson, "merchantAccountCode"),
            getFieldOrEmpty(notificationItemJson, "merchantReference"),
            getAmountField(notificationItemJson, "value"),
            getAmountField(notificationItemJson, "currency"),
            getFieldOrEmpty(notificationItemJson, "eventCode"),
            getFieldOrEmpty(notificationItemJson, "success")
        };
        return String.join(":", fields);
    }

    private String getFieldOrEmpty(String json, String field) {
        String val = extractJsonField(json, field);
        if (val != null) {
            return val;
        }
        return "";
    }

    private String getAmountField(String json, String subField) {
        int amountIdx = json.indexOf("\"amount\"");
        if (amountIdx < 0) {
            return "";
        }
        int braceOpen = json.indexOf('{', amountIdx);
        if (braceOpen < 0) {
            return "";
        }
        int braceClose = json.indexOf('}', braceOpen);
        if (braceClose < 0) {
            return "";
        }
        String amountBlock = json.substring(braceOpen, braceClose + 1);
        String val = extractJsonField(amountBlock, subField);
        if (val != null) {
            return val;
        }
        return "";
    }

    private String extractNotificationItem(String json) {
        String marker = "\"NotificationRequestItem\"";
        int idx = json.indexOf(marker);
        if (idx < 0) {
            return null;
        }
        int braceOpen = json.indexOf('{', idx + marker.length());
        if (braceOpen < 0) {
            return null;
        }
        int depth = 0;
        for (int i = braceOpen; i < json.length(); i++) {
            if (json.charAt(i) == '{') {
                depth++;
            } else if (json.charAt(i) == '}') {
                depth--;
                if (depth == 0) {
                    return json.substring(braceOpen, i + 1);
                }
            }
        }
        return null;
    }

    private String extractAdditionalDataField(String json, String field) {
        int adIdx = json.indexOf("\"additionalData\"");
        if (adIdx < 0) {
            return null;
        }
        int braceOpen = json.indexOf('{', adIdx);
        if (braceOpen < 0) {
            return null;
        }
        int braceClose = json.indexOf('}', braceOpen);
        if (braceClose < 0) {
            return null;
        }
        String block = json.substring(braceOpen, braceClose + 1);
        return extractJsonField(block, field);
    }

    private byte[] computeHmac(byte[] data, byte[] keyBytes) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new WebhookSignatureException("adyen", "HMAC computation failed: " + e.getMessage());
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
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        if (start >= json.length()) {
            return null;
        }
        char first = json.charAt(start);
        if (first == '"') {
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
