package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.domain.ErrorResponse;
import uk.gov.di.ipv.cri.passport.dto.DcsCheckRequestDto;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.validation.ValidationResult;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class PassportHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PassportHandler.class);
    private static final ObjectMapper objectMapper = createObjectMapper();
    private final Set<String> oauthQueryParamKeySet = Set.of("response_type", "client_id", "redirect_uri", "scope");

    private static ObjectMapper createObjectMapper() {
        var objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        return objectMapper;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        var queryStringParameters = getQueryStringParametersAsMap(input);
        var validationResult = validateQueryStringParameters(queryStringParameters);
        if (!validationResult.isValid()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, validationResult.getError());
        }

        try {
            // TODO What the hell do we do with this?
            AuthenticationRequest.parse(queryStringParameters);
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }

        DcsCheckRequestDto dcsCheckRequestDto;
        try {
            dcsCheckRequestDto = objectMapper.readValue(input.getBody(), DcsCheckRequestDto.class);

            //todo hook -- add call to proxy (DSC values to be sent to passportservice.postValidPassportRequest

        } catch (JsonProcessingException e) {
            LOGGER.error("Passport form data could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, dcsCheckRequestDto);
    }

    private Map<String, List<String>> getQueryStringParametersAsMap(
            APIGatewayProxyRequestEvent input) {
        if (input.getQueryStringParameters() != null) {
            return input.getQueryStringParameters().entrySet().stream()
                    .collect(
                            Collectors.toMap(
                                    Map.Entry::getKey, entry -> List.of(entry.getValue())));
        }
        return Collections.emptyMap();
    }

    private ValidationResult<ErrorResponse> validateQueryStringParameters(
            Map<String, List<String>> queryStringParameters) {
        if (Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty()) {
            LOGGER.error("No query string parameters found");
            return new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }
        if (!queryStringParameters.keySet().equals(oauthQueryParamKeySet)) {
            var missingParams = new HashSet<>(oauthQueryParamKeySet);
            missingParams.removeIf(queryStringParameters.keySet()::contains);
            LOGGER.error("Missing required query parameters from request: " + missingParams);
            return new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }
        return ValidationResult.createValidResult();
    }
}
