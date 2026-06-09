package io.quarkiverse.webhooks.runtime;

import java.time.Duration;

import org.eclipse.microprofile.config.Config;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.providers.AdyenWebhookProvider;
import io.quarkiverse.webhooks.providers.GitHubWebhookProvider;
import io.quarkiverse.webhooks.providers.ShopifyWebhookProvider;
import io.quarkiverse.webhooks.providers.SlackWebhookProvider;
import io.quarkiverse.webhooks.providers.StandardWebhooksProvider;
import io.quarkiverse.webhooks.providers.StripeWebhookProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

@ApplicationScoped
public class WebhookProviders {

    private static final int DEFAULT_WINDOW_SECONDS = 300;

    @Inject
    Config config;

    @Produces
    @ApplicationScoped
    public WebhookProvider stripeProvider() {
        int window = replayWindow("stripe");
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
        int window = replayWindow("standard");
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

    @Produces
    @ApplicationScoped
    public WebhookProvider slackProvider() {
        int window = replayWindow("slack");
        return new SlackWebhookProvider(window);
    }

    private int replayWindow(String providerName) {
        String key = "quarkus.webhooks.providers." + providerName + ".replay-window";
        return config.getOptionalValue(key, Duration.class)
                .map(d -> (int) d.toSeconds())
                .orElse(DEFAULT_WINDOW_SECONDS);
    }
}
