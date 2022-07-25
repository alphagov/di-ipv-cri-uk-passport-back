package uk.gov.di.ipv.cri.passport.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;

public class ApiGatewayResponseGenerator {

    private static final String JSON_CONTENT_TYPE_VALUE = "application/json";
    private static final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private static final Logger LOGGER = LoggerFactory.getLogger(ApiGatewayResponseGenerator.class);

    private ApiGatewayResponseGenerator() {}

    public static APIGatewayProxyResponseEvent proxyJwtResponse(int statusCode, String payload) {
        Map<String, String> responseHeaders = Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt");
        return proxyResponse(statusCode, payload, responseHeaders);
    }

    public static <T> APIGatewayProxyResponseEvent proxyJsonResponse(int statusCode, T body) {
        Map<String, String> responseHeaders =
                Map.of(HttpHeaders.CONTENT_TYPE, JSON_CONTENT_TYPE_VALUE);

        try {
            return proxyResponse(statusCode, generateResponseBody(body), responseHeaders);
        } catch (JsonProcessingException e) {
            LOGGER.error("Unable to generateApiGatewayProxyErrorResponse", e);
            return proxyResponse(500, "Internal server error", Collections.emptyMap());
        }
    }

    public static APIGatewayProxyResponseEvent proxyResponse(
            int statusCode, String body, Map<String, String> headers) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setHeaders(headers);
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);

        return apiGatewayProxyResponseEvent;
    }

    private static <T> String generateResponseBody(T body) throws JsonProcessingException {
        return objectMapper.writeValueAsString(body);
    }
}
