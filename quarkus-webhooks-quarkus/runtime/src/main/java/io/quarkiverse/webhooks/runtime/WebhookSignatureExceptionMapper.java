package io.quarkiverse.webhooks.runtime;

import java.util.Map;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import io.quarkiverse.webhooks.exception.WebhookSignatureException;

@Provider
public class WebhookSignatureExceptionMapper implements ExceptionMapper<WebhookSignatureException> {

    @Override
    public Response toResponse(WebhookSignatureException exception) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(Map.of(
                        "error", "webhook_signature_invalid",
                        "provider", exception.getProvider(),
                        "message", exception.getReason()))
                .build();
    }
}
