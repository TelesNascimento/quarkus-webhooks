package io.quarkiverse.webhooks.deployment;

import io.quarkiverse.webhooks.runtime.WebhookProviders;
import io.quarkiverse.webhooks.runtime.WebhookRouteHandler;
import io.quarkiverse.webhooks.runtime.WebhookSignatureExceptionMapper;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

public class WebhooksProcessor {

    private static final String FEATURE = "webhooks";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

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
