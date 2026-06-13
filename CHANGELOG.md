# Changelog

All notable changes to quarkus-webhooks are documented here.

## [Unreleased]

### Added

- `GitHubWebhookProvider` - HMAC-SHA256 hex verification against `X-Hub-Signature-256`
- `ShopifyWebhookProvider` - HMAC-SHA256 Base64 verification against `X-Shopify-Hmac-SHA256`
- `SlackWebhookProvider` - HMAC-SHA256 hex verification with mandatory 5-minute timestamp window
- `WebhookProviderUtils` - shared cryptographic utilities (hexToBytesSafe, computeHmac, findHeader, extractJsonField)
- `quarkus-webhooks-testing` module - `MockWebhookSender` for integration tests (unique in the Java ecosystem)
- `sign()` default method on `WebhookProvider` SPI - enables mock sender and custom test utilities
- Dual secret rotation via `quarkus.webhooks.providers.{name}.retiring-secret`
- `@Blocking` annotation on route handler - HMAC computation no longer blocks Vert.x event loop
- Provider name validation against `[a-zA-Z0-9_-]+` - prevents config key injection
- Catch-all `Throwable` handler on route - unexpected exceptions return 401, never 500

### Changed

- `StripeWebhookProvider` - uses shared `WebhookProviderUtils`; added `MAX_SIGNATURES=10` DoS guard; replay window bounds enforced (60-3600s)
- `StandardWebhooksProvider` - uses shared `WebhookProviderUtils`; replay window bounds enforced
- `AdyenWebhookProvider` - uses shared `WebhookProviderUtils`
- `WebhookRouteHandler` - now uses `WebhooksConfig` for replay window wiring; hardened with `@Blocking`, catch-all, and path validation

### Security

- `hexToBytesSafe()` always returns `byte[32]` - prevents timing oracle on invalid hex input
- Negative timestamps rejected explicitly before `Math.abs()` - prevents edge case bypass
- Replay window upper bound (3600s) - prevents disabling protection via `Integer.MAX_VALUE`

## [0.1.0] - 2026-05

### Added

- `StripeWebhookProvider` - HMAC-SHA256 hex, timestamp replay protection
- `AdyenWebhookProvider` - HMAC-SHA256 Base64 with hex key
- `StandardWebhooksProvider` - HMAC-SHA256 Base64 with `whsec_` prefix support
- `WebhookProvider` SPI - `name()`, `verify()`, `extractEventId()`, `extractEventType()`
- `WebhookSignatureException` - typed exception with provider and reason
- Quarkus extension - Vert.x route `POST /webhooks/{provider}` with raw body capture
- `WebhooksConfig` - MicroProfile Config mapping per provider
- `WebhookProviderContractTest` - abstract test class for SPI compliance validation
