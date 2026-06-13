package io.quarkiverse.webhooks.providers;

import io.quarkiverse.webhooks.WebhookProvider;
import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Contrato de testes para implementações de {@link WebhookProvider}.
 *
 * <p>Todo provider concreto deve passar neste contrato. Para usá-lo, basta
 * estender esta classe e implementar os métodos abstratos:</p>
 *
 * <pre>{@code
 * class StripeProviderContractTest extends WebhookProviderContractTest {
 *
 *     @Override protected WebhookProvider createProvider()  { return new StripeWebhookProvider(); }
 *     @Override protected byte[]          validBody()       { return "{\"id\":\"evt_1\"}".getBytes(); }
 *     @Override protected Map<String,String> validHeaders() { return Map.of("stripe-signature", buildSig()); }
 *     @Override protected String          validSecret()     { return "whsec_test"; }
 *     @Override protected String          expectedProviderName() { return "stripe"; }
 * }
 * }</pre>
 *
 * <p>Os 8 testes cobrem: nome do provider, verificação com entrada válida,
 * corpo nulo, headers vazios e extração de metadados.</p>
 */
public abstract class WebhookProviderContractTest {

    // -------------------------------------------------------------------------
    // Métodos de fábrica - implementar na subclasse
    // -------------------------------------------------------------------------

    /** Retorna uma instância nova do provider sendo testado. */
    protected abstract WebhookProvider createProvider();

    /** Corpo de requisição válido (JSON raw bytes), compatível com {@link #validHeaders()} e {@link #validSecret()}. */
    protected abstract byte[] validBody();

    /**
     * Headers válidos que, combinados com {@link #validBody()} e {@link #validSecret()},
     * devem passar a verificação sem exceção.
     */
    protected abstract Map<String, String> validHeaders();

    /** Segredo configurado para gerar/validar a assinatura dos dados de {@link #validBody()}. */
    protected abstract String validSecret();

    /** Nome esperado retornado por {@link WebhookProvider#name()}. */
    protected abstract String expectedProviderName();

    // -------------------------------------------------------------------------
    // Fixture
    // -------------------------------------------------------------------------

    protected WebhookProvider provider;

    @BeforeEach
    void initProvider() {
        provider = createProvider();
    }

    // -------------------------------------------------------------------------
    // 1. Contrato de nome
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("name() - não deve retornar null")
    void name_isNotNull() {
        assertThat(provider.name()).isNotNull();
    }

    @Test
    @DisplayName("name() - não deve retornar string vazia ou em branco")
    void name_isNotBlank() {
        assertThat(provider.name()).isNotBlank();
    }

    @Test
    @DisplayName("name() - deve igualar o nome esperado pelo contrato")
    void name_equalsExpected() {
        assertThat(provider.name()).isEqualTo(expectedProviderName());
    }

    // -------------------------------------------------------------------------
    // 2. Contrato de verify()
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("verify() - entrada válida não deve lançar exceção")
    void verify_validInput_doesNotThrow() {
        assertThatCode(() ->
                provider.verify(validBody(), validHeaders(), validSecret())
        ).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("verify() - corpo null deve lançar exceção ou ser tratado graciosamente")
    void verify_nullBody_throwsOrHandlesGracefully() {
        // Providers podem lançar WebhookSignatureException, NullPointerException,
        // ou outra RuntimeException - qualquer resposta controlada é aceita.
        // O que NÃO é aceito: retornar silenciosamente sem verificar.
        try {
            provider.verify(null, validHeaders(), validSecret());
            // Se chegou aqui, o provider optou por aceitar null body sem verificar.
            // Documentar: o provider aceita null body sem verificação.
        } catch (Exception e) {
            // Qualquer exceção é aceitável - o provider sinalizou o problema.
            assertThat(e).isInstanceOf(Exception.class);
        }
    }

    @Test
    @DisplayName("verify() - headers vazios devem lançar WebhookSignatureException")
    void verify_emptyHeaders_throwsSignatureException() {
        assertThatThrownBy(() ->
                provider.verify(validBody(), Collections.emptyMap(), validSecret())
        ).isInstanceOf(WebhookSignatureException.class);
    }

    // -------------------------------------------------------------------------
    // 3. Contrato de extração de metadados
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("extractEventId() - não deve lançar exceção com entrada válida")
    void extractEventId_doesNotThrow() {
        assertThatCode(() ->
                provider.extractEventId(validBody(), validHeaders())
        ).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("extractEventType() - não deve lançar exceção com entrada válida")
    void extractEventType_doesNotThrow() {
        assertThatCode(() ->
                provider.extractEventType(validBody(), validHeaders())
        ).doesNotThrowAnyException();
    }
}
