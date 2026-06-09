package io.quarkiverse.webhooks.util;

import io.quarkiverse.webhooks.exception.WebhookSignatureException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("WebhookProviderUtils")
class WebhookProviderUtilsTest {

    // -------------------------------------------------------------------------
    // findHeader
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("findHeader")
    class FindHeader {

        @Test
        @DisplayName("null map returns null")
        void nullMap_returnsNull() {
            assertThat(WebhookProviderUtils.findHeader(null, "Content-Type")).isNull();
        }

        @Test
        @DisplayName("null name returns null")
        void nullName_returnsNull() {
            Map<String, String> headers = Map.of("Content-Type", "application/json");
            assertThat(WebhookProviderUtils.findHeader(headers, null)).isNull();
        }

        @Test
        @DisplayName("empty map returns null")
        void emptyMap_returnsNull() {
            assertThat(WebhookProviderUtils.findHeader(Collections.emptyMap(), "X-Header")).isNull();
        }

        @Test
        @DisplayName("exact case match returns value")
        void exactCase_returnsValue() {
            Map<String, String> headers = Map.of("stripe-signature", "t=123,v1=abc");
            assertThat(WebhookProviderUtils.findHeader(headers, "stripe-signature"))
                    .isEqualTo("t=123,v1=abc");
        }

        @Test
        @DisplayName("case-insensitive uppercase lookup returns value")
        void caseInsensitive_uppercaseLookup() {
            Map<String, String> headers = Map.of("stripe-signature", "t=123,v1=abc");
            assertThat(WebhookProviderUtils.findHeader(headers, "Stripe-Signature"))
                    .isEqualTo("t=123,v1=abc");
        }

        @Test
        @DisplayName("case-insensitive lowercase lookup returns value")
        void caseInsensitive_lowercaseLookup() {
            Map<String, String> headers = Map.of("Webhook-ID", "msg_001");
            assertThat(WebhookProviderUtils.findHeader(headers, "webhook-id"))
                    .isEqualTo("msg_001");
        }
    }

    // -------------------------------------------------------------------------
    // hexToBytesSafe
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("hexToBytesSafe")
    class HexToBytesSafe {

        @Test
        @DisplayName("null input returns byte[32] of zeros")
        void nullInput_returnsByteArray32() {
            byte[] result = WebhookProviderUtils.hexToBytesSafe(null);
            assertThat(result).hasSize(32).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("empty string returns byte[32] of zeros")
        void emptyString_returnsByteArray32() {
            byte[] result = WebhookProviderUtils.hexToBytesSafe("");
            assertThat(result).hasSize(32).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("string shorter than 64 chars returns byte[32] of zeros")
        void shortString_returnsByteArray32() {
            byte[] result = WebhookProviderUtils.hexToBytesSafe("deadbeef");
            assertThat(result).hasSize(32).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("valid lowercase 64-char hex returns correct bytes")
        void validLowercase_returnsCorrectBytes() {
            String hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
            byte[] result = WebhookProviderUtils.hexToBytesSafe(hex);
            assertThat(result).hasSize(32);
            assertThat(result[0]).isEqualTo((byte) 0x00);
            assertThat(result[1]).isEqualTo((byte) 0x01);
            assertThat(result[31]).isEqualTo((byte) 0x1f);
        }

        @Test
        @DisplayName("valid uppercase 64-char hex returns correct bytes")
        void validUppercase_returnsCorrectBytes() {
            String hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
            byte[] result = WebhookProviderUtils.hexToBytesSafe(hex);
            assertThat(result).hasSize(32);
            assertThat(result[0]).isEqualTo((byte) 0x00);
            assertThat(result[31]).isEqualTo((byte) 0x1f);
        }

        @Test
        @DisplayName("invalid chars (GG) in 64-char string returns byte[32] of zeros")
        void invalidChars_returnsByteArray32() {
            String hex = "GG01020304050607080910111213141516171819202122232425262728293031";
            byte[] result = WebhookProviderUtils.hexToBytesSafe(hex);
            assertThat(result).hasSize(32).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("always returns byte[32] regardless of input")
        void alwaysReturnsByte32() {
            assertThat(WebhookProviderUtils.hexToBytesSafe(null)).hasSize(32);
            assertThat(WebhookProviderUtils.hexToBytesSafe("")).hasSize(32);
            assertThat(WebhookProviderUtils.hexToBytesSafe("abcd")).hasSize(32);
            assertThat(WebhookProviderUtils.hexToBytesSafe("a".repeat(64))).hasSize(32);
            assertThat(WebhookProviderUtils.hexToBytesSafe("0".repeat(64))).hasSize(32);
        }
    }

    // -------------------------------------------------------------------------
    // computeHmac
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("computeHmac")
    class ComputeHmac {

        @Test
        @DisplayName("null data throws WebhookSignatureException")
        void nullData_throws() {
            byte[] key = "secret".getBytes(StandardCharsets.UTF_8);
            assertThatThrownBy(() -> WebhookProviderUtils.computeHmac(null, key, "test"))
                    .isInstanceOf(WebhookSignatureException.class)
                    .hasMessageContaining("data is null");
        }

        @Test
        @DisplayName("null key (byte[]) throws WebhookSignatureException")
        void nullKeyBytes_throws() {
            byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
            assertThatThrownBy(() -> WebhookProviderUtils.computeHmac(data, (byte[]) null, "test"))
                    .isInstanceOf(WebhookSignatureException.class)
                    .hasMessageContaining("key is null");
        }

        @Test
        @DisplayName("null secret (String) throws WebhookSignatureException")
        void nullSecretString_throws() {
            byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
            assertThatThrownBy(() -> WebhookProviderUtils.computeHmac(data, (String) null, "test"))
                    .isInstanceOf(WebhookSignatureException.class)
                    .hasMessageContaining("secret is null");
        }

        @Test
        @DisplayName("valid call returns byte[32]")
        void validCall_returnsByte32() {
            byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
            byte[] key = "secret".getBytes(StandardCharsets.UTF_8);
            byte[] result = WebhookProviderUtils.computeHmac(data, key, "test");
            assertThat(result).hasSize(32);
        }

        @Test
        @DisplayName("same input produces same output (deterministic)")
        void deterministic() {
            byte[] data = "same-payload".getBytes(StandardCharsets.UTF_8);
            byte[] key = "same-secret".getBytes(StandardCharsets.UTF_8);
            byte[] first = WebhookProviderUtils.computeHmac(data, key, "test");
            byte[] second = WebhookProviderUtils.computeHmac(data, key, "test");
            assertThat(first).isEqualTo(second);
        }
    }

    // -------------------------------------------------------------------------
    // extractJsonField
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("extractJsonField")
    class ExtractJsonField {

        @Test
        @DisplayName("null json returns null")
        void nullJson_returnsNull() {
            assertThat(WebhookProviderUtils.extractJsonField(null, "id")).isNull();
        }

        @Test
        @DisplayName("null fieldName returns null")
        void nullFieldName_returnsNull() {
            assertThat(WebhookProviderUtils.extractJsonField("{\"id\":\"123\"}", null)).isNull();
        }

        @Test
        @DisplayName("field not found returns null")
        void fieldNotFound_returnsNull() {
            assertThat(WebhookProviderUtils.extractJsonField("{\"type\":\"charge\"}", "id")).isNull();
        }

        @Test
        @DisplayName("simple string field returns value")
        void simpleString_returnsValue() {
            String json = "{\"id\":\"evt_001\",\"type\":\"charge.succeeded\"}";
            assertThat(WebhookProviderUtils.extractJsonField(json, "id")).isEqualTo("evt_001");
            assertThat(WebhookProviderUtils.extractJsonField(json, "type")).isEqualTo("charge.succeeded");
        }

        @Test
        @DisplayName("numeric field returns string representation")
        void numericField_returnsStringValue() {
            String json = "{\"amount\":1000,\"currency\":\"USD\"}";
            assertThat(WebhookProviderUtils.extractJsonField(json, "amount")).isEqualTo("1000");
        }

        @Test
        @DisplayName("escaped quotes in value are unescaped")
        void escapedQuotes_inValue_areUnescaped() {
            String json = "{\"message\":\"say \\\"hello\\\"\",\"status\":\"ok\"}";
            assertThat(WebhookProviderUtils.extractJsonField(json, "message"))
                    .isEqualTo("say \"hello\"");
        }

        @Test
        @DisplayName("field name appearing inside another field's value is not matched prematurely")
        void fieldNameInsideValue_notMatchedPrematurely() {
            String json = "{\"data\":\"the id is unknown\",\"id\":\"evt_real\"}";
            assertThat(WebhookProviderUtils.extractJsonField(json, "id")).isEqualTo("evt_real");
        }

        @Test
        @DisplayName("empty JSON object returns null for any field")
        void emptyObject_returnsNull() {
            assertThat(WebhookProviderUtils.extractJsonField("{}", "id")).isNull();
        }
    }
}
