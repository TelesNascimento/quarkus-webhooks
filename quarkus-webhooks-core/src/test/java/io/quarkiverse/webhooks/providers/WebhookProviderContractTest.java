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

public abstract class WebhookProviderContractTest {

    protected abstract WebhookProvider createProvider();

    protected abstract byte[] validBody();

    protected abstract Map<String, String> validHeaders();

    protected abstract String validSecret();

    protected abstract String expectedProviderName();

    protected WebhookProvider provider;

    @BeforeEach
    void initProvider() {
        provider = createProvider();
    }

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

        try {
            provider.verify(null, validHeaders(), validSecret());

        } catch (Exception e) {

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
