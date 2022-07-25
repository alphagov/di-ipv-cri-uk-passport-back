package uk.gov.di.ipv.cri.passport.initialisesession;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.JarValidationException;
import uk.gov.di.ipv.cri.passport.library.exceptions.RecoverableJarValidationException;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;
import uk.gov.di.ipv.cri.passport.library.validation.JarValidator;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PRIVATE_KEY_1;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.JWE_OBJECT_STRING;

@ExtendWith(MockitoExtension.class)
class InitialiseSessionHandlerTest {

    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of("passport_session_id", "test-session-id", "client_id", "TEST");

    @Mock private JarValidator jarValidator;

    @Mock private AuditService auditService;

    @Mock private PassportSessionService passportSessionService;

    @InjectMocks private InitialiseSessionHandler underTest;

    private SignedJWT signedJWT;

    @Mock Context context;

    @BeforeEach
    void setUp() throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException {
        Map<String, List<String>> shared_claim =
                Map.of(
                        "givenNames", Arrays.asList("Daniel", "Dan", "Danny"),
                        "dateOfBirths", Arrays.asList("01/01/1980", "02/01/1980"),
                        "addresses", Collections.singletonList("123 random street, M13 7GE"));

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .expirationTime(new Date(Instant.now().plusSeconds(1000).getEpochSecond()))
                        .issueTime(new Date())
                        .notBeforeTime(new Date())
                        .subject("test-user-id")
                        .audience("test-audience")
                        .issuer("test-issuer")
                        .claim("response_type", "code")
                        .claim("redirect_uri", "http://example.com")
                        .claim("state", "test-state")
                        .claim("client_id", "test-client")
                        .claim("shared_claims", shared_claim)
                        .build();

        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
        signedJWT.sign(new ECDSASigner(getPrivateKey()));
    }

    @Test
    void shouldReturn200WhenGivenValidJWT() throws Exception {
        when(jarValidator.decryptJWE(any(JWEObject.class))).thenReturn(signedJWT);
        when(jarValidator.validateRequestJwt(any(), anyString()))
                .thenReturn(signedJWT.getJWTClaimsSet());
        when(passportSessionService.generatePassportSession(any())).thenReturn("12345");

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(JWE_OBJECT_STRING);

        var response = underTest.handleRequest(event, context);
        assertEquals(200, response.getStatusCode());
        verify(auditService).sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_START);
    }

    @Test
    void shouldReturnClaimsAsJsonFromJWT() throws Exception {
        when(jarValidator.decryptJWE(any(JWEObject.class))).thenReturn(signedJWT);
        when(jarValidator.validateRequestJwt(any(), anyString()))
                .thenReturn(signedJWT.getJWTClaimsSet());
        when(passportSessionService.generatePassportSession(any())).thenReturn("12345");

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(JWE_OBJECT_STRING);

        var response = underTest.handleRequest(event, context);

        Map<String, Object> claims =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        Map<String, Object> sharedClaims =
                OBJECT_MAPPER.convertValue(claims.get("shared_claims"), new TypeReference<>() {});
        assertEquals(Arrays.asList("01/01/1980", "02/01/1980"), sharedClaims.get("dateOfBirths"));
        assertEquals(
                Collections.singletonList("123 random street, M13 7GE"),
                sharedClaims.get("addresses"));
        assertEquals(Arrays.asList("Daniel", "Dan", "Danny"), sharedClaims.get("givenNames"));
    }

    @Test
    void shouldReturn400IfMissingJWT() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(null);

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT.getCode(), error.get("code"));
        assertEquals(
                ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfFailedToParseJWTClaimSet()
            throws JsonProcessingException, JarValidationException, ParseException {
        when(jarValidator.decryptJWE(any(JWEObject.class))).thenReturn(signedJWT);
        when(jarValidator.validateRequestJwt(any(), anyString()))
                .thenReturn(signedJWT.getJWTClaimsSet());
        when(passportSessionService.generatePassportSession(any()))
                .thenThrow(new ParseException("Failed to parse jwt claim set", 0));

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(JWE_OBJECT_STRING);

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getCode(), error.get("code"));
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfFailedToParseJWTClaimSetWhenGeneratingSession()
            throws JsonProcessingException, JarValidationException, ParseException {
        when(jarValidator.decryptJWE(any(JWEObject.class))).thenReturn(signedJWT);
        JWTClaimsSet myMock = mock(JWTClaimsSet.class);
        when(myMock.getJSONObjectClaim(anyString()))
                .thenThrow(new ParseException("Failed to parse jwt claim set", 0));
        when(jarValidator.validateRequestJwt(any(), anyString())).thenReturn(myMock);
        when(passportSessionService.generatePassportSession(any())).thenReturn("12345");

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(JWE_OBJECT_STRING);

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getCode(), error.get("code"));
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfClientIdIsNotSet() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> noClientId = new HashMap<>(TEST_EVENT_HEADERS);
        noClientId.remove("client_id");
        event.setHeaders(noClientId);

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER.getCode(), error.get("code"));
        assertEquals(
                ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn302WhenValidationFails() throws Exception {
        when(jarValidator.decryptJWE(any(JWEObject.class))).thenReturn(signedJWT);
        when(jarValidator.validateRequestJwt(any(), anyString()))
                .thenThrow(new JarValidationException(OAuth2Error.INVALID_REQUEST_OBJECT));

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(JWE_OBJECT_STRING);

        var response = underTest.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(302, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorResponse.getCode());
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getDescription(),
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn302WithRedirectUriWhenValidationFailsButIsRecoverable() throws Exception {
        when(jarValidator.decryptJWE(any(JWEObject.class))).thenReturn(signedJWT);
        when(jarValidator.validateRequestJwt(any(), anyString()))
                .thenThrow(
                        new RecoverableJarValidationException(
                                OAuth2Error.INVALID_REQUEST_OBJECT,
                                "http://redirect-url.com",
                                null));

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(JWE_OBJECT_STRING);

        var response = underTest.handleRequest(event, context);

        assertEquals(302, response.getStatusCode());
        assertEquals(
                "{\"redirect_uri\":\"http://redirect-url.com\",\"oauth_error\":{\"error_description\":\"Invalid request JWT\",\"error\":\"invalid_request_object\"}}",
                response.getBody());
    }

    @Test
    void shouldReturn302WithRedirectUriAndStateIfPresentWhenValidationFailsButIsRecoverable()
            throws Exception {
        when(jarValidator.decryptJWE(any(JWEObject.class))).thenReturn(signedJWT);
        when(jarValidator.validateRequestJwt(any(), anyString()))
                .thenThrow(
                        new RecoverableJarValidationException(
                                OAuth2Error.INVALID_REQUEST_OBJECT,
                                "http://redirect-url.com",
                                "xyz"));

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(JWE_OBJECT_STRING);

        var response = underTest.handleRequest(event, context);

        assertEquals(302, response.getStatusCode());
        assertEquals(
                "{\"redirect_uri\":\"http://redirect-url.com\",\"state\":\"xyz\",\"oauth_error\":{\"error_description\":\"Invalid request JWT\",\"error\":\"invalid_request_object\"}}",
                response.getBody());
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY_1)));
    }

    private ErrorObject createErrorObjectFromResponse(String responseBody)
            throws com.nimbusds.oauth2.sdk.ParseException {
        HTTPResponse httpErrorResponse = new HTTPResponse(400);
        httpErrorResponse.setContentType(ContentType.APPLICATION_JSON.getType());
        httpErrorResponse.setContent(responseBody);
        return ErrorObject.parse(httpErrorResponse);
    }
}
