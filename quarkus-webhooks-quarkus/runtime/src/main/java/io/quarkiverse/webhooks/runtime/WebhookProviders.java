package io.quarkiverse.webhooks.runtime;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.providers.AdyenWebhookProvider;
import io.quarkiverse.webhooks.providers.GitHubWebhookProvider;
import io.quarkiverse.webhooks.providers.ShopifyWebhookProvider;
import io.quarkiverse.webhooks.providers.StandardWebhooksProvider;
import io.quarkiverse.webhooks.providers.StripeWebhookProvider;
import io.quarkiverse.webhooks.runtime.config.WebhooksConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

@ApplicationScoped
public class WebhookProviders {

    @Inject
    WebhooksConfig config;

    @Produces
    @ApplicationScoped
    public WebhookProvider stripeProvider() {
        WebhooksConfig.ProviderConfig cfg = config.providers().get("stripe");
        int window = cfg != null ? (int) cfg.replayWindow().toSeconds() : 300;
        return new StripeWebhookProvider(window);
    }

    @Produces
    @ApplicationScoped
    public WebhookProvider adyenProvider() {
        return new AdyenWebhookProvider();
    }

    @Produces
    @ApplicationScoped
    public WebhookProvider standardProvider() {
        WebhooksConfig.ProviderConfig cfg = config.providers().get("standard");
        int window = cfg != null ? (int) cfg.replayWindow().toSeconds() : 300;
        return new StandardWebhooksProvider(window);
    }

    @Produces
    @ApplicationScoped
    public WebhookProvider githubProvider() {
        return new GitHubWebhookProvider();
    }

    @Produces
    @ApplicationScoped
    public WebhookProvider shopifyProvider() {
        return new ShopifyWebhookProvider();
    }
}
