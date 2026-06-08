package io.quarkiverse.webhooks.runtime;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.providers.AdyenWebhookProvider;
import io.quarkiverse.webhooks.providers.StandardWebhooksProvider;
import io.quarkiverse.webhooks.providers.StripeWebhookProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

/**
 * CDI producer that registers the built-in {@link WebhookProvider} implementations as beans.
 *
 * <p>These are discovered by {@link WebhookRouteHandler} via {@code @Any Instance<WebhookProvider>}.</p>
 *
 * <p>Applications can add custom providers by simply declaring additional
 * {@code @ApplicationScoped} beans that implement {@link WebhookProvider}.</p>
 */
@ApplicationScoped
public class WebhookProviders {

    /**
     * Built-in Stripe provider.
     * Secret is read from {@code quarkus.webhooks.providers.stripe.secret}.
     */
    @Produces
    @ApplicationScoped
    public WebhookProvider stripeProvider() {
        return new StripeWebhookProvider();
    }

    /**
     * Built-in Adyen provider.
     * Secret is read from {@code quarkus.webhooks.providers.adyen.secret}.
     */
    @Produces
    @ApplicationScoped
    public WebhookProvider adyenProvider() {
        return new AdyenWebhookProvider();
    }

    /**
     * Built-in Standard Webhooks provider.
     * Secret is read from {@code quarkus.webhooks.providers.standard.secret}.
     */
    @Produces
    @ApplicationScoped
    public WebhookProvider standardProvider() {
        return new StandardWebhooksProvider();
    }
}
