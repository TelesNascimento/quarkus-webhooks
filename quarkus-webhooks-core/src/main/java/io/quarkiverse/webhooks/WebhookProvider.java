package io.quarkiverse.webhooks;

import java.util.Map;

public interface WebhookProvider {

    String name();

    void verify(byte[] rawBody, Map<String, String> headers, String secret);

    String extractEventId(byte[] rawBody, Map<String, String> headers);

    String extractEventType(byte[] rawBody, Map<String, String> headers);

    /**
     * Generates the HTTP headers required to send a valid signed webhook request.
     * Used by testing utilities to generate signed payloads.
     *
     * @param rawBody the request body bytes
     * @param secret  the signing secret
     * @return Map of header name to header value
     * @throws UnsupportedOperationException if this provider does not support signing
     */
    default java.util.Map<String, String> sign(byte[] rawBody, String secret) {
        throw new UnsupportedOperationException("Signing not supported for provider: " + name());
    }
}
