package io.quarkiverse.webhooks.deployment;

import io.quarkiverse.webhooks.runtime.WebhookProviders;
import io.quarkiverse.webhooks.runtime.WebhookRouteHandler;
import io.quarkiverse.webhooks.runtime.WebhookSignatureExceptionMapper;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

/**
 * Quarkus build-time processor for the Webhooks extension.
 */
public class WebhooksProcessor {

    private static final String FEATURE = "webhooks";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    /**
     * Register all runtime beans as unremovable so Arc does not eliminate them.
     * WebhookRouteHandler is used by Vert.x (not injected anywhere visible to Arc),
     * so it must be explicitly marked unremovable.
     */
    @BuildStep
    AdditionalBeanBuildItem registerBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        WebhookRouteHandler.class,
                        WebhookProviders.class,
                        WebhookSignatureExceptionMapper.class)
                .setUnremovable()
                .build();
    }
}
