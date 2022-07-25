package uk.gov.di.ipv.cri.passport.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.AuthParams;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.net.URISyntaxException;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BuildClientOauthResponseHandlerTest {
    private static final String PASSPORT_SESSION_ID_HEADER_NAME = "passport_session_id";
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of(PASSPORT_SESSION_ID_HEADER_NAME, "12345");

    @Mock private Context context;
    @Mock private AuthorizationCodeService mockAuthorizationCodeService;
    @Mock private PassportSessionService mockPassportSessionService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private AuditService mockAuditService;

    private AuthorizationCode authorizationCode;
    private BuildClientOauthResponseHandler handler;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();
        handler =
                new BuildClientOauthResponseHandler(
                        mockAuthorizationCodeService,
                        mockPassportSessionService,
                        mockAuditService,
                        mockConfigurationService);
    }

    @Test
    void shouldReturn200OnSuccessfulRequest()
            throws JsonProcessingException, SqsException, URISyntaxException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(generatePassportSessionItem());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(
                        authorizationCode.getValue(),
                        TEST_EVENT_HEADERS.get(PASSPORT_SESSION_ID_HEADER_NAME));

        verify(mockAuditService).sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_END);

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode.toString())
                        .addParameter("state", "test-state")
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
    }

    @Test
    void shouldReturn200WhenStateNotInSession() throws Exception {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);

        PassportSessionItem passportSessionItem = generatePassportSessionItem();
        passportSessionItem.getAuthParams().setState(null);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(passportSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode.toString())
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
    }

    @Test
    void shouldReturn400WhenPassportSessionIdHeaderIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn500IfAuditServiceFails() throws SqsException, JsonProcessingException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(generatePassportSessionItem());
        doThrow(new SqsException("Test error"))
                .when(mockAuditService)
                .sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_END);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR.getCode(), responseBody.get("error"));
        assertEquals("Test error", responseBody.get("error_description"));
    }

    @Test
    void shouldReturn500OnInvalidUriStringForRedirectUri() throws JsonProcessingException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        PassportSessionItem passportSessionItem = generatePassportSessionItem();
        passportSessionItem.getAuthParams().setRedirectUri("https://inv^alid.com");
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(passportSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    void shouldReturnAccessDeniedResponseIfNoPassportAttemptHasBeenMade()
            throws JsonProcessingException, SqsException, URISyntaxException {
        PassportSessionItem passportSessionItem = generatePassportSessionItem();
        passportSessionItem.setAttemptCount(0);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(passportSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("error", OAuth2Error.ACCESS_DENIED.getCode())
                        .addParameter(
                                "error_description", OAuth2Error.ACCESS_DENIED.getDescription())
                        .addParameter("state", "test-state")
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
    }

    private PassportSessionItem generatePassportSessionItem() {
        PassportSessionItem item = new PassportSessionItem();

        AuthParams authParams =
                new AuthParams("code", "ipv-core", "test-state", "https://example.com");

        item.setAuthParams(authParams);
        item.setPassportSessionId(SecureTokenHelper.generate());
        item.setCreationDateTime(new Date().toString());
        item.setUserId("user-id");
        item.setAttemptCount(1);

        return item;
    }
}
