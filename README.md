# quarkus-webhooks

Webhook signature verification for Quarkus and plain Java.

Fills the gap documented in [Quarkus Issue #53715](https://github.com/quarkusio/quarkus/issues/53715) and closes recurring pain points in [stripe-java #1199](https://github.com/stripe/stripe-java/issues/1199) and [stripe-java #1151](https://github.com/stripe/stripe-java/issues/1151).

## Features

- **6 providers out of the box**: Stripe, Adyen, Standard Webhooks, GitHub, Shopify, Slack
- **Framework-agnostic core** — use without Quarkus if needed
- **Quarkus extension** — Vert.x route intercepts raw body before JAX-RS, zero body-consumption issues
- **Constant-time comparison** (`MessageDigest.isEqual`) — timing attack protection
- **Replay protection** — configurable timestamp window (default 5 min) for Stripe, Standard, Slack
- **Dual secret rotation** — zero-downtime key rotation via `retiring-secret`
- **MockWebhookSender** — the only Java library with a generic in-process mock sender for tests

## Installation

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>io.quarkiverse.webhooks</groupId>
    <artifactId>quarkus-webhooks</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

For testing:

```xml
<dependency>
    <groupId>io.quarkiverse.webhooks</groupId>
    <artifactId>quarkus-webhooks-testing</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

## Configuration (`application.properties`)

```properties
quarkus.webhooks.providers.stripe.secret=whsec_...
quarkus.webhooks.providers.github.secret=github_secret
quarkus.webhooks.providers.shopify.secret=shopify_secret
quarkus.webhooks.providers.slack.secret=slack_signing_secret
quarkus.webhooks.providers.standard.secret=whsec_...
quarkus.webhooks.providers.adyen.secret=0a1b2c3d...

# Optional: replay protection window (default PT5M)
quarkus.webhooks.providers.stripe.replay-window=PT10M

# Optional: zero-downtime key rotation
quarkus.webhooks.providers.stripe.retiring-secret=whsec_old...
```

## Quarkus Extension — Automatic Route

The extension registers `POST /webhooks/{provider}` via Vert.x. The route:
1. Reads raw body bytes before JAX-RS
2. Verifies signature — returns `401` on failure
3. Passes verified data to downstream JAX-RS endpoints via `RoutingContext`

```java
@Path("/webhooks")
@ApplicationScoped
public class WebhookResource {

    @POST
    @Path("/{provider}")
    public Response handle(@Context RoutingContext ctx) {
        String eventId   = ctx.get("webhook.eventId");
        String eventType = ctx.get("webhook.eventType");
        byte[] rawBody   = ctx.get("webhook.rawBody");
        // process event...
        return Response.ok().build();
    }
}
```

## Framework-Agnostic Core

Use any provider without Quarkus:

```java
// Stripe
new StripeWebhookProvider().verify(rawBodyBytes, headers, secret);

// GitHub
new GitHubWebhookProvider().verify(rawBodyBytes, headers, secret);

// Shopify — note: Base64, not hex
new ShopifyWebhookProvider().verify(rawBodyBytes, headers, secret);

// Slack — timestamp header is mandatory
new SlackWebhookProvider().verify(rawBodyBytes, headers, secret);

// Standard Webhooks (Svix, OpenAI, Anthropic, Vercel...)
new StandardWebhooksProvider().verify(rawBodyBytes, headers, secret);

// Adyen
new AdyenWebhookProvider().verify(rawBodyBytes, headers, hmacKeyHex);
```

`verify()` throws `WebhookSignatureException` on failure (maps to HTTP 401 in the extension).

## Supported Providers

| Provider | Header verified | Encoding | Timestamp protection |
|----------|----------------|----------|---------------------|
| **Stripe** | `Stripe-Signature: t=...,v1=<hex>` | Hex | 5 min (configurable) |
| **GitHub** | `X-Hub-Signature-256: sha256=<hex>` | Hex | None |
| **Shopify** | `X-Shopify-Hmac-SHA256: <base64>` | Base64 | None |
| **Slack** | `X-Slack-Signature: v0=<hex>` + `X-Slack-Request-Timestamp` | Hex | 5 min (mandatory) |
| **Standard Webhooks** | `webhook-signature: v1,<base64>` + `webhook-id` + `webhook-timestamp` | Base64 | 5 min (configurable) |
| **Adyen** | `HmacSignature` in body JSON | Base64 | None |

## Testing with MockWebhookSender

`quarkus-webhooks-testing` provides a fluent mock sender. No manual HMAC computation needed:

```java
@QuarkusTest
class PaymentWebhookTest {

    @Inject
    Instance<WebhookProvider> allProviders;

    @Test
    void testStripePaymentSucceeded() {
        MockWebhookSender sender = new MockWebhookSender(
            allProviders.stream().collect(Collectors.toList())
        );

        sender.provider("stripe")
              .secret("whsec_test")
              .payload("{\"id\":\"evt_1\",\"type\":\"payment_intent.succeeded\"}")
              .send("/webhooks/stripe")
              .statusCode(404); // 404 = signature valid, no JAX-RS endpoint
    }

    @Test
    void testSlackMessage() {
        MockWebhookSender sender = new MockWebhookSender(
            allProviders.stream().collect(Collectors.toList())
        );

        sender.provider("slack")
              .secret("xoxb-test-signing-secret")
              .payload("{\"type\":\"event_callback\",\"event\":{\"type\":\"message\"}}")
              .header("X-Slack-Team-Id", "T12345")
              .send("/webhooks/slack")
              .statusCode(404);
    }
}
```

Providers that support `sign()`: Stripe, GitHub, Shopify, Slack, Standard Webhooks.
Adyen is excluded (non-standard field-based signing).

## Security

- `MessageDigest.isEqual()` constant-time comparison on all providers
- `hexToBytesSafe()` always returns `byte[32]` — prevents timing oracle on hex parsing
- `@Blocking` annotation on route handler — HMAC never blocks the Vert.x event loop
- Provider name validated against `[a-zA-Z0-9_-]+` before use as config key
- Replay window enforced: min 60s, max 3600s — prevents `Integer.MAX_VALUE` disabling protection
- Negative timestamps rejected before `Math.abs()` — prevents edge case bypass
- Catch-all `Throwable` handler — unexpected exceptions return 401, never 500 with stack trace

## Implementing a Custom Provider

Extend `WebhookProviderContractTest` to validate SPI compliance automatically:

```java
class MyProviderTest extends WebhookProviderContractTest {

    @Override protected WebhookProvider createProvider()        { return new MyProvider(); }
    @Override protected byte[] validBody()                      { return "{}".getBytes(); }
    @Override protected Map<String, String> validHeaders()      { return Map.of("X-My-Sig", buildSig()); }
    @Override protected String validSecret()                    { return "my-secret"; }
    @Override protected String expectedProviderName()           { return "my-provider"; }
}
```

## Project Structure

```
quarkus-webhooks/
├── quarkus-webhooks-core/          # Framework-agnostic verification
│   └── src/main/java/io/quarkiverse/webhooks/
│       ├── WebhookProvider.java                  # SPI interface
│       ├── exception/WebhookSignatureException.java
│       ├── util/WebhookProviderUtils.java        # Shared crypto utilities
│       └── providers/
│           ├── StripeWebhookProvider.java
│           ├── AdyenWebhookProvider.java
│           ├── StandardWebhooksProvider.java
│           ├── GitHubWebhookProvider.java
│           ├── ShopifyWebhookProvider.java
│           └── SlackWebhookProvider.java
├── quarkus-webhooks-quarkus/       # Quarkus extension (CDI, Vert.x route, config)
└── quarkus-webhooks-testing/       # MockWebhookSender for integration tests
```

## Related

- [Quarkus Issue #53715](https://github.com/quarkusio/quarkus/issues/53715) — CSRF extension bypass needed for webhook paths
- [stripe-java #1199](https://github.com/stripe/stripe-java/issues/1199) — Stripe webhook signature fails in Quarkus
- [stripe-java #1151](https://github.com/stripe/stripe-java/issues/1151) — Raw body handling in JAX-RS
- [hub4j/github-api #1376](https://github.com/hub4j/github-api/issues/1376) — Validating GitHub webhook payloads
- [Standard Webhooks Spec](https://www.standardwebhooks.com)
