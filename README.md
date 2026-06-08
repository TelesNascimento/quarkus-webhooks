# quarkus-webhooks

Verificação de assinaturas de webhooks para Quarkus e Java puro.  
Preenche a lacuna documentada na [Quarkus Issue #53715](https://github.com/quarkusio/quarkus/issues/53715).

---

## Providers disponíveis

| Provider            | Método de verificação                     | Destaques                                     |
|---------------------|-------------------------------------------|-----------------------------------------------|
| **Stripe**          | HMAC-SHA256(`timestamp.body`)             | Proteção contra replay, suporte a key rotation |
| **Adyen**           | HMAC-SHA256(campos em ordem fixa)         | Chave hex, saída Base64                        |
| **Standard Webhooks** | HMAC-SHA256(`id.timestamp.body`)        | Spec aberta em [standardwebhooks.com](https://www.standardwebhooks.com) |

---

## Quick Start — Core (sem framework)

```java
// Stripe
StripeWebhookProvider stripe = new StripeWebhookProvider();
stripe.verify(rawBodyBytes, headers, secret); // lança WebhookSignatureException se inválido

// Adyen
AdyenWebhookProvider adyen = new AdyenWebhookProvider();
adyen.verify(rawBodyBytes, headers, hmacKeyHex);

// Standard Webhooks
StandardWebhooksProvider standard = new StandardWebhooksProvider();
standard.verify(rawBodyBytes, headers, secret);
```

Extração de metadados para idempotência e roteamento:

```java
String eventId   = stripe.extractEventId(rawBodyBytes, headers);   // "evt_123"
String eventType = stripe.extractEventType(rawBodyBytes, headers);  // "payment_intent.succeeded"
```

---

## Quick Start — Quarkus (chegando na v0.2)

```
POST /webhooks/stripe  →  corpo raw verificado antes de chegar ao JAX-RS
```

O handler Vert.x interceptará a rota, verificará a assinatura e só repassará ao resource se válida.

---

## Segurança

- Todas as comparações usam `MessageDigest.isEqual()` — proteção contra timing attacks
- Proteção contra replay: janela de **5 minutos** (configurável no `StripeWebhookProvider`)
- Nunca registre o secret em logs
- `WebhookSignatureException` mapeia para HTTP 401 na camada de framework

---

## Executando os testes

```bash
export JAVA_HOME=$(brew --prefix)/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
mvn test -f quarkus-webhooks-core/pom.xml
```

---

## Estrutura do projeto

```
quarkus-webhooks/
├── quarkus-webhooks-core/          # Verificação pura — zero dependências de runtime
│   └── src/main/java/io/quarkiverse/webhooks/
│       ├── WebhookProvider.java                        # SPI principal
│       ├── exception/WebhookSignatureException.java    # Exceção tipada
│       └── providers/
│           ├── StripeWebhookProvider.java
│           ├── AdyenWebhookProvider.java
│           └── StandardWebhooksProvider.java
└── (quarkus-webhooks-runtime — v0.2, em andamento)
```

---

## Contrato de testes para novos providers

Ao implementar um novo `WebhookProvider`, estenda `WebhookProviderContractTest` para garantir conformidade com o SPI:

```java
class MeuProviderContractTest extends WebhookProviderContractTest {

    @Override protected WebhookProvider   createProvider()       { return new MeuProvider(); }
    @Override protected byte[]            validBody()            { return "{}".getBytes(); }
    @Override protected Map<String,String> validHeaders()        { return Map.of("x-sig", buildSig()); }
    @Override protected String            validSecret()          { return "meu-secret"; }
    @Override protected String            expectedProviderName() { return "meu-provider"; }
}
```

---

## Status

| Versão | Escopo                                               | Testes |
|--------|------------------------------------------------------|--------|
| **v0.1** | Core providers: Stripe, Adyen, Standard Webhooks   | 25+    |
| **v0.2** | Handler Quarkus Vert.x (em andamento)              | —      |

---

## Relacionados

- [Quarkus Issue #53715](https://github.com/quarkusio/quarkus/issues/53715) — ausência de suporte nativo a verificação de webhooks
- Escopo diferente de `quarkus-github-app` (que trata exclusivamente webhooks do GitHub)
- [Standard Webhooks Spec](https://www.standardwebhooks.com)
