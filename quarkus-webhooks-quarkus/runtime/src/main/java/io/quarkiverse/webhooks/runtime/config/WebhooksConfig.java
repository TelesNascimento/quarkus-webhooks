package io.quarkiverse.webhooks.runtime.config;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Quarkus config mapping for the Webhooks extension.
 *
 * <p>Example {@code application.properties}:</p>
 * <pre>
 * quarkus.webhooks.providers.stripe.secret=whsec_abc123
 * quarkus.webhooks.providers.stripe.replay-window=PT10M
 *
 * quarkus.webhooks.providers.adyen.secret=1A2B3C4D...
 * </pre>
 */
@ConfigMapping(prefix = "quarkus.webhooks")
public interface WebhooksConfig {

    /**
     * Per-provider configuration, keyed by provider name (e.g. {@code stripe}, {@code adyen}).
     */
    Map<String, ProviderConfig> providers();

    /**
     * Configuration for a single webhook provider.
     */
    interface ProviderConfig {

        /**
         * The webhook signing secret for this provider.
         * For Stripe, this starts with {@code whsec_}.
         * For Adyen, this is a hex-encoded HMAC key.
         */
        Optional<String> secret();

        /**
         * Replay-attack protection window.
         * Webhooks with a timestamp older than this value are rejected.
         * Defaults to {@code PT5M} (5 minutes).
         */
        @WithDefault("PT5M")
        Duration replayWindow();
    }
}
