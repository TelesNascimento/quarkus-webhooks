package io.quarkiverse.webhooks.runtime;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Vert.x Reactive Route handler for webhook signature verification.
 *
 * <p>Uses {@link RoutingContext#getBody()} to access raw bytes <strong>before</strong> JAX-RS
 * processes the body — the same pattern used by
 * <a href="https://github.com/quarkiverse/quarkus-github-app">quarkus-github-app</a> (Red Hat).
 * Solves the raw body problem documented in Quarkus issue #22444.</p>
 *
 * <p><strong>Route:</strong> {@code POST /webhooks/{provider}}</p>
 * <ol>
 *   <li>Reads raw body bytes via {@link RoutingContext#getBody()}</li>
 *   <li>Resolves the matching {@link WebhookProvider} by name</li>
 *   <li>Reads the signing secret from {@link WebhooksConfig}</li>
 *   <li>Calls {@link WebhookProvider#verify} — throws {@link WebhookSignatureException} if invalid</li>
 *   <li>Stores verified body + event metadata in the {@link RoutingContext} for downstream handlers</li>
 * </ol>
 */
@ApplicationScoped
@RouteBase(path = "/webhooks")
public class WebhookRouteHandler {

    @Inject
    @Any
    Instance<WebhookProvider> providers;

    /**
     * MicroProfile Config API — reads quarkus.webhooks.providers.{name}.secret
     * without requiring @ConfigMapping registration in the extension.
     */
    @Inject
    Config config;

    @Route(path = "/:provider", methods = Route.HttpMethod.POST)
    public void handle(RoutingContext ctx) {
        String providerName = ctx.pathParam("provider");

        // Resolve the provider by name
        WebhookProvider provider = findProvider(providerName);
        if (provider == null) {
            ctx.response()
                    .setStatusCode(404)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"unknown_provider\",\"provider\":\"" + providerName + "\"}");
            return;
        }

        // Get raw body bytes — Vert.x reads these BEFORE JAX-RS touches the request
        Buffer body = ctx.getBody();
        if (body == null || body.length() == 0) {
            ctx.response()
                    .setStatusCode(400)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"empty_body\"}");
            return;
        }
        byte[] rawBody = body.getBytes();

        // Convert headers to Map<String, String> (Vert.x MultiMap → plain Map)
        Map<String, String> headers = new HashMap<>();
        ctx.request().headers().forEach(entry -> headers.put(entry.getKey(), entry.getValue()));

        // Resolve secret via MicroProfile Config: quarkus.webhooks.providers.{name}.secret
        String secret = config.getOptionalValue(
                "quarkus.webhooks.providers." + providerName + ".secret", String.class)
                .orElse("");

        // Verify signature — 401 on failure
        try {
            provider.verify(rawBody, headers, secret);
        } catch (WebhookSignatureException e) {
            ctx.response()
                    .setStatusCode(401)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"webhook_signature_invalid\",\"provider\":\"" + providerName
                            + "\",\"reason\":\"" + e.getReason() + "\"}");
            return;
        }

        // Store verified data in RoutingContext for downstream JAX-RS endpoints
        ctx.put("webhook.provider", providerName);
        ctx.put("webhook.rawBody", rawBody);
        ctx.put("webhook.eventId", provider.extractEventId(rawBody, headers));
        ctx.put("webhook.eventType", provider.extractEventType(rawBody, headers));

        // Pass control to the next handler (JAX-RS endpoint)
        ctx.next();
    }

    private WebhookProvider findProvider(String name) {
        for (WebhookProvider p : providers) {
            if (p.name().equals(name)) {
                return p;
            }
        }
        return null;
    }
}
