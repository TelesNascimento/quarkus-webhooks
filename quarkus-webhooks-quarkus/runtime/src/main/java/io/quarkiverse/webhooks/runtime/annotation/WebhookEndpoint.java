package io.quarkiverse.webhooks.runtime.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a JAX-RS resource method as a webhook endpoint that requires signature verification.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * @POST
 * @Path("/stripe")
 * @WebhookEndpoint(provider = "stripe", secretConfig = "${stripe.webhook.secret}")
 * public Response handleStripe(byte[] body) { ... }
 * }</pre>
 *
 * <p>The Quarkus extension will intercept the request before the method is invoked,
 * resolve the secret from config, and call the appropriate {@link io.quarkiverse.webhooks.WebhookProvider}
 * to verify the signature. If verification fails, a {@code 401 Unauthorized} response is returned.</p>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface WebhookEndpoint {

    /**
     * The provider identifier — e.g. {@code "stripe"}, {@code "adyen"}, {@code "standard"}.
     * Must match the value returned by {@link io.quarkiverse.webhooks.WebhookProvider#name()}.
     */
    String provider();

    /**
     * Config key that holds the webhook secret.
     * Supports Quarkus config expressions, e.g. {@code "${stripe.webhook.secret}"}.
     */
    String secretConfig();
}
