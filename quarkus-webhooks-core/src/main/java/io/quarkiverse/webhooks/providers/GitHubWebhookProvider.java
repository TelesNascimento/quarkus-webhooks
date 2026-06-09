package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkiverse.webhooks.util.WebhookProviderUtils;

import java.security.MessageDigest;
import java.util.Map;

public class GitHubWebhookProvider implements WebhookProvider {

    private static final String HEADER_SIGNATURE = "X-Hub-Signature-256";
    private static final String HEADER_DELIVERY = "X-GitHub-Delivery";
    private static final String HEADER_EVENT = "X-GitHub-Event";
    private static final String SIGNATURE_PREFIX = "sha256=";

    @Override
    public String name() {
        return "github";
    }

    @Override
    public void verify(byte[] rawBody, Map<String, String> headers, String secret) {
        if (rawBody == null) {
            throw new WebhookSignatureException("github", "missing request body");
        }
        String signatureHeader = WebhookProviderUtils.findHeader(headers, HEADER_SIGNATURE);
        if (signatureHeader == null || signatureHeader.isBlank()) {
            throw new WebhookSignatureException("github", "missing X-Hub-Signature-256 header");
        }
        if (!signatureHeader.startsWith(SIGNATURE_PREFIX)) {
            throw new WebhookSignatureException("github",
                    "invalid signature format - expected sha256= prefix");
        }
        String receivedHex = signatureHeader.substring(SIGNATURE_PREFIX.length());
        byte[] expected = WebhookProviderUtils.computeHmac(rawBody, secret, "github");
        byte[] received = WebhookProviderUtils.hexToBytesSafe(receivedHex);
        if (!MessageDigest.isEqual(expected, received)) {
            throw new WebhookSignatureException("github", "signature mismatch");
        }
    }

    @Override
    public Map<String, String> sign(byte[] rawBody, String secret) {
        byte[] hmac = WebhookProviderUtils.computeHmac(rawBody, secret, "github");
        String hexHmac = WebhookProviderUtils.bytesToHex(hmac);
        return Map.of(HEADER_SIGNATURE, SIGNATURE_PREFIX + hexHmac);
    }

    @Override
    public String extractEventId(byte[] rawBody, Map<String, String> headers) {
        return WebhookProviderUtils.findHeader(headers, HEADER_DELIVERY);
    }

    @Override
    public String extractEventType(byte[] rawBody, Map<String, String> headers) {
        return WebhookProviderUtils.findHeader(headers, HEADER_EVENT);
    }
}
