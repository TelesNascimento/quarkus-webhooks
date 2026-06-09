package io.quarkiverse.webhooks.util;

import io.quarkiverse.webhooks.exception.WebhookSignatureException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared cryptographic and parsing utilities for {@link io.quarkiverse.webhooks.WebhookProvider} implementations.
 *
 * <p>All methods in this class are stateless and thread-safe.</p>
 *
 * <h2>Constant-time comparison</h2>
 * <p>Use {@link #hexToBytesSafe(String)} combined with {@link java.security.MessageDigest#isEqual(byte[], byte[])}
 * to compare HMAC signatures without timing oracle. {@code hexToBytesSafe} always returns {@code byte[32]}
 * (HMAC-SHA256 output size) — returning zeros for invalid input — so {@code isEqual} always performs
 * a full 32-byte comparison regardless of input validity.</p>
 *
 * <h2>Header lookup</h2>
 * <p>HTTP headers are case-insensitive per RFC 7230. Use {@link #findHeader(java.util.Map, String)}
 * for case-insensitive lookups instead of {@code headers.get(name)}.</p>
 */
public final class WebhookProviderUtils {

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int HMAC_SHA256_BYTES = 32;
    private static final int HMAC_SHA256_HEX_CHARS = 64;

    private WebhookProviderUtils() {}

    public static String findHeader(Map<String, String> headers, String name) {
        if (headers == null || name == null) {
            return null;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    public static byte[] hexToBytesSafe(String hex) {
        byte[] result = new byte[HMAC_SHA256_BYTES];
        boolean valid = (hex != null && hex.length() == HMAC_SHA256_HEX_CHARS);
        for (int i = 0; i < HMAC_SHA256_HEX_CHARS; i += 2) {
            int high = -1;
            int low = -1;
            if (valid) {
                high = Character.digit(hex.charAt(i), 16);
                low = Character.digit(hex.charAt(i + 1), 16);
            }
            if (high < 0 || low < 0) {
                valid = false;
            }
            if (high >= 0 && low >= 0) {
                result[i / 2] = (byte) ((high << 4) | low);
            }
        }
        return result;
    }

    public static byte[] hexToBytes(String hex) {
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

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] computeHmac(byte[] data, byte[] keyBytes, String provider) {
        if (data == null) {
            throw new WebhookSignatureException(provider, "HMAC computation failed: data is null");
        }
        if (keyBytes == null) {
            throw new WebhookSignatureException(provider, "HMAC computation failed: key is null");
        }
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(keyBytes, HMAC_SHA256));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new WebhookSignatureException(provider, "HMAC computation failed: " + e.getMessage());
        }
    }

    public static byte[] computeHmac(byte[] data, String secret, String provider) {
        if (secret == null) {
            throw new WebhookSignatureException(provider, "HMAC computation failed: secret is null");
        }
        return computeHmac(data, secret.getBytes(StandardCharsets.UTF_8), provider);
    }

    public static String extractJsonField(String json, String fieldName) {
        if (json == null || fieldName == null) {
            return null;
        }
        try {
            String pattern = "\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*"
                    + "(?:\"((?:[^\"\\\\]|\\\\.)*)\"|([^,}\\]\\s][^,}\\]]*))";;
            Matcher matcher = Pattern.compile(pattern).matcher(json);
            if (!matcher.find()) {
                return null;
            }
            int matchStart = matcher.start();
            int unescapedQuotes = 0;
            for (int i = 0; i < matchStart; i++) {
                if (json.charAt(i) == '"' && (i == 0 || json.charAt(i - 1) != '\\')) {
                    unescapedQuotes++;
                }
            }
            if (unescapedQuotes % 2 != 0) {
                matcher.region(matchStart + 1, json.length());
                if (!matcher.find()) {
                    return null;
                }
            }
            String quoted = matcher.group(1);
            String unquoted = matcher.group(2);
            if (quoted != null) {
                return unescapeJson(quoted);
            }
            if (unquoted != null) {
                String trimmed = unquoted.trim();
                if ("null".equals(trimmed)) {
                    return null;
                }
                return trimmed;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String unescapeJson(String s) {
        return s.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\/", "/")
                .replace("\\b", "\b")
                .replace("\\f", "\f")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t");
    }
}
