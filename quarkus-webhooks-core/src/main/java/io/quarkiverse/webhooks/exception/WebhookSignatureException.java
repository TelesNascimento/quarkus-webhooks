package io.quarkiverse.webhooks.exception;

public class WebhookSignatureException extends RuntimeException {

    private final String provider;
    private final String reason;

    public WebhookSignatureException(String provider, String reason) {
        super("Webhook signature verification failed [provider=" + provider + "]: " + reason);
        this.provider = provider;
        this.reason = reason;
    }

    public String getProvider() {
        return provider;
    }

    public String getReason() {
        return reason;
    }
}
