package io.quarkiverse.webhooks.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@DisplayName("WebhookSignatureException")
class WebhookSignatureExceptionTest {

    private static final String PROVIDER = "stripe";
    private static final String REASON   = "invalid signature";

    // -------------------------------------------------------------------------
    // 1. Hierarquia de tipos
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("isRuntimeException - deve estender RuntimeException")
    void isRuntimeException() {
        WebhookSignatureException ex = new WebhookSignatureException(PROVIDER, REASON);
        assertThat(ex).isInstanceOf(RuntimeException.class);
    }

    // -------------------------------------------------------------------------
    // 2. Armazenamento de campos
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("storesProviderName - construtor armazena o provider")
    void storesProviderName() {
        WebhookSignatureException ex = new WebhookSignatureException("adyen", REASON);
        assertThat(ex.getProvider()).isEqualTo("adyen");
    }

    @Test
    @DisplayName("storesReason - construtor armazena o reason")
    void storesReason() {
        WebhookSignatureException ex = new WebhookSignatureException(PROVIDER, "timestamp expirado");
        assertThat(ex.getReason()).isEqualTo("timestamp expirado");
    }

    // -------------------------------------------------------------------------
    // 3. Mensagem da exceção
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("messageContainsProviderAndReason - getMessage() inclui provider e reason")
    void messageContainsProviderAndReason() {
        WebhookSignatureException ex = new WebhookSignatureException(PROVIDER, REASON);
        assertThat(ex.getMessage())
                .contains(PROVIDER)
                .contains(REASON);
    }

    // -------------------------------------------------------------------------
    // 4. Getters
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("getProvider - retorna exatamente o valor passado no construtor")
    void getProvider_returnsProvider() {
        WebhookSignatureException ex = new WebhookSignatureException("standard", REASON);
        assertThat(ex.getProvider()).isEqualTo("standard");
    }

    @Test
    @DisplayName("getReason - retorna exatamente o valor passado no construtor")
    void getReason_returnsReason() {
        WebhookSignatureException ex = new WebhookSignatureException(PROVIDER, "header ausente");
        assertThat(ex.getReason()).isEqualTo("header ausente");
    }

    // -------------------------------------------------------------------------
    // 5. Comportamento polimórfico
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("canBeCaughtAsRuntimeException - pode ser capturada como RuntimeException")
    void canBeCaughtAsRuntimeException() {
        assertThatCode(() -> {
            try {
                throw new WebhookSignatureException(PROVIDER, REASON);
            } catch (RuntimeException e) {
                // capturada corretamente - não deve re-lançar
            }
        }).doesNotThrowAnyException();
    }

    // -------------------------------------------------------------------------
    // 6. Robustez com valores nulos
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("nullProvider - construtor aceita provider null sem NPE")
    void nullProvider_handledGracefully() {
        assertThatCode(() -> {
            WebhookSignatureException ex = new WebhookSignatureException(null, REASON);
            // getProvider() deve retornar null sem lançar exceção
            assertThat(ex.getProvider()).isNull();
            // getMessage() não deve explodir com null provider
            assertThat(ex.getMessage()).isNotNull();
        }).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("nullReason - construtor aceita reason null sem NPE")
    void nullReason_handledGracefully() {
        assertThatCode(() -> {
            WebhookSignatureException ex = new WebhookSignatureException(PROVIDER, null);
            assertThat(ex.getReason()).isNull();
            assertThat(ex.getMessage()).isNotNull();
        }).doesNotThrowAnyException();
    }
}
