package io.quarkiverse.webhooks;

import java.util.Map;

public interface WebhookProvider {

    String name();

    void verify(byte[] rawBody, Map<String, String> headers, String secret);

    String extractEventId(byte[] rawBody, Map<String, String> headers);

    String extractEventType(byte[] rawBody, Map<String, String> headers);
}
