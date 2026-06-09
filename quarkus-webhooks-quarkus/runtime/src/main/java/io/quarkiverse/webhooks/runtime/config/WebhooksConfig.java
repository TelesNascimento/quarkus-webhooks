package io.quarkiverse.webhooks.runtime.config;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.webhooks")
public interface WebhooksConfig {

    Map<String, ProviderConfig> providers();

    interface ProviderConfig {

        Optional<String> secret();

        @WithDefault("PT5M")
        Duration replayWindow();

        Optional<String> retiringSecret();
    }
}
