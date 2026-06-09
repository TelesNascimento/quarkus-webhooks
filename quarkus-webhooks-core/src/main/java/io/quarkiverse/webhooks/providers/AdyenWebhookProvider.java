package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

public class AdyenWebhookProvider implements WebhookProvider {

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
        byte[] keyBytes = WebhookProviderUtils.hexToBytes(secret);
        if (keyBytes == null) {
            throw new WebhookSignatureException("adyen", "invalid HMAC key - must be hex-encoded string");
        }
        byte[] computedHmac = WebhookProviderUtils.computeHmac(
                dataToSign.getBytes(StandardCharsets.UTF_8), keyBytes, "adyen");
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
            return WebhookProviderUtils.extractJsonField(item, "pspReference");
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
            return WebhookProviderUtils.extractJsonField(item, "eventCode");
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
        String val = WebhookProviderUtils.extractJsonField(json, field);
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
        String val = WebhookProviderUtils.extractJsonField(amountBlock, subField);
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
                        return json.substring(braceOpen, i + 1);
                    }
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
        int depth = 0;
        boolean inString = false;
        int braceClose = -1;
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
                        braceClose = i;
                        break;
                    }
                }
            }
        }
        if (braceClose < 0) {
            return null;
        }
        String block = json.substring(braceOpen, braceClose + 1);
        return WebhookProviderUtils.extractJsonField(block, field);
    }
}
