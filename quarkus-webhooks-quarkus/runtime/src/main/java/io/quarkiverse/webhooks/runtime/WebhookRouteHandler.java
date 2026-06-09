package io.quarkiverse.webhooks.runtime;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.eclipse.microprofile.config.Config;
import org.jboss.logging.Logger;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.smallrye.common.annotation.Blocking;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

@ApplicationScoped
@RouteBase(path = "/webhooks")
public class WebhookRouteHandler {

    private static final Logger LOG = Logger.getLogger(WebhookRouteHandler.class);
    private static final Pattern VALID_PROVIDER_NAME = Pattern.compile("^[a-zA-Z0-9_-]+$");
    private static final int MAX_PROVIDER_NAME_LENGTH = 64;

    @Inject
    @Any
    Instance<WebhookProvider> providers;

    @Inject
    Config config;

    @Route(path = "/:provider", methods = Route.HttpMethod.POST)
    @Blocking
    public void handle(RoutingContext ctx) {
        String providerName = ctx.pathParam("provider");

        if (!isValidProviderName(providerName)) {
            ctx.response()
                    .setStatusCode(404)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"unknown_provider\"}");
            return;
        }

        WebhookProvider provider = findProvider(providerName);
        if (provider == null) {
            ctx.response()
                    .setStatusCode(404)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"unknown_provider\",\"provider\":\"" + providerName + "\"}");
            return;
        }

        Buffer body = ctx.getBody();
        if (body == null || body.length() == 0) {
            ctx.response()
                    .setStatusCode(400)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"empty_body\"}");
            return;
        }
        byte[] rawBody = body.getBytes();

        Map<String, String> headers = new HashMap<>();
        ctx.request().headers().forEach(entry -> headers.put(entry.getKey(), entry.getValue()));

        String secretKey = "quarkus.webhooks.providers." + providerName + ".secret";
        String retiringKey = "quarkus.webhooks.providers." + providerName + ".retiring-secret";
        String secret = config.getOptionalValue(secretKey, String.class).orElse("");
        String retiringSecret = config.getOptionalValue(retiringKey, String.class).orElse(null);

        try {
            verifyWithFallback(provider, rawBody, headers, secret, retiringSecret);
        } catch (WebhookSignatureException e) {
            LOG.warnf("Webhook signature verification failed [provider=%s]: %s", providerName, e.getReason());
            ctx.response()
                    .setStatusCode(401)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"webhook_signature_invalid\",\"provider\":\"" + providerName + "\"}");
            return;
        } catch (Throwable e) {
            LOG.errorf(e, "Unexpected error verifying webhook [provider=%s]", providerName);
            ctx.response()
                    .setStatusCode(401)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"webhook_verification_failed\"}");
            return;
        }

        ctx.put("webhook.provider", providerName);
        ctx.put("webhook.rawBody", rawBody);
        ctx.put("webhook.eventId", provider.extractEventId(rawBody, headers));
        ctx.put("webhook.eventType", provider.extractEventType(rawBody, headers));

        ctx.next();
    }

    private void verifyWithFallback(WebhookProvider provider, byte[] rawBody,
            Map<String, String> headers, String secret, String retiringSecret) {
        try {
            provider.verify(rawBody, headers, secret);
        } catch (WebhookSignatureException e) {
            if (retiringSecret == null || retiringSecret.isBlank()) {
                throw e;
            }
            if (e.getReason() != null && e.getReason().contains("timestamp")) {
                throw e;
            }
            try {
                provider.verify(rawBody, headers, retiringSecret);
                LOG.warnf("Webhook verified with retiring secret [provider=%s] - rotate your secrets",
                        provider.name());
            } catch (WebhookSignatureException ignored) {
                throw e;
            }
        }
    }

    private boolean isValidProviderName(String name) {
        return name != null
                && name.length() <= MAX_PROVIDER_NAME_LENGTH
                && VALID_PROVIDER_NAME.matcher(name).matches();
    }

    private WebhookProvider findProvider(String name) {
        for (WebhookProvider provider : providers) {
            if (provider.name().equals(name)) {
                return provider;
            }
        }
        return null;
    }
}
