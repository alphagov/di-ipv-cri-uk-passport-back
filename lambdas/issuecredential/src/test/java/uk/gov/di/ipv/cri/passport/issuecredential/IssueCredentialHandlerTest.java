package uk.gov.di.ipv.cri.passport.issuecredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEvent;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.NamePartType;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.NameParts;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredential;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.DcsPassportCheckService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.MAX_JWT_TTL;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.VERIFIABLE_CREDENTIAL_ISSUER;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PRIVATE_KEY_1;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PUBLIC_JWK_1;

@ExtendWith(MockitoExtension.class)
class IssueCredentialHandlerTest {

    private static final String TEST_RESOURCE_ID = UUID.randomUUID().toString();
    public static final String PASSPORT_NUMBER = "1234567890";
    public static final String SURNAME = "Tattsyrup";
    public static final List<String> FORENAMES = List.of("Tubbs");
    public static final String DATE_OF_BIRTH = "1984-09-28";
    public static final String EXPIRY_DATE = "2024-09-03";
    public static final String SUBJECT = "subject";
    public static final String TEST_PASSPORT_SESSION_ID = "a-test-passport-session-id";

    @Mock private Context mockContext;
    @Mock private DcsPassportCheckService mockDcsPassportCheckService;
    @Mock private AccessTokenService mockAccessTokenService;
    @Mock private AuditService mockAuditService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private PassportSessionService mockPassportSessionService;
    @Spy private ECDSASigner ecSigner = new ECDSASigner(getPrivateKey());
    @InjectMocks private IssueCredentialHandler issueCredentialHandler;

    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private final DcsPayload dcsPayload =
            new DcsPayload(
                    PASSPORT_NUMBER,
                    SURNAME,
                    FORENAMES,
                    LocalDate.parse(DATE_OF_BIRTH),
                    LocalDate.parse(EXPIRY_DATE));
    private final Evidence evidence = new Evidence(UUID.randomUUID().toString(), 4, 2, null);
    private final String userId = "test-user-id";
    private final String clientId = "test-client-id";
    private final PassportCheckDao passportCheckDao =
            new PassportCheckDao(TEST_RESOURCE_ID, dcsPayload, evidence, userId, clientId);
    private Map<String, String> responseBody = new HashMap<>();

    IssueCredentialHandlerTest() throws Exception {}

    @Test
    void shouldReturn200OnSuccessfulDcsCredentialRequest() throws SqsException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        accessToken.getValue(),
                        TEST_RESOURCE_ID,
                        Instant.now().plusSeconds(3600).toString(),
                        UUID.randomUUID().toString());
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        setRequestBodyAsPlainJWT(event);

        when(mockAccessTokenService.getAccessTokenItem(accessToken.getValue()))
                .thenReturn(accessTokenItem);

        when(mockDcsPassportCheckService.getDcsPassportCheck(anyString()))
                .thenReturn(passportCheckDao);

        mockConfigurationServiceCalls();

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);

        ArgumentCaptor<AuditEvent> argumentCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(argumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_VC_ISSUED,
                argumentCaptor.getValue().getEventName());

        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturn200WhenResourceIdInSessionDcsCredentialRequest() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        accessToken.getValue(),
                        null,
                        Instant.now().plusSeconds(3600).toString(),
                        TEST_PASSPORT_SESSION_ID);
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        setRequestBodyAsPlainJWT(event);

        when(mockAccessTokenService.getAccessTokenItem(accessToken.getValue()))
                .thenReturn(accessTokenItem);
        PassportSessionItem passportSessionItem = new PassportSessionItem();
        passportSessionItem.setLatestDcsResponseResourceId(TEST_RESOURCE_ID);

        when(mockPassportSessionService.getPassportSession(TEST_PASSPORT_SESSION_ID))
                .thenReturn(passportSessionItem);

        when(mockDcsPassportCheckService.getDcsPassportCheck(TEST_RESOURCE_ID))
                .thenReturn(passportCheckDao);

        mockConfigurationServiceCalls();

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);

        assertEquals(200, response.getStatusCode());
        assertEquals(
                "test-user-id", SignedJWT.parse(response.getBody()).getJWTClaimsSet().getSubject());
    }

    private void mockConfigurationServiceCalls() {
        when(mockConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("TEST");
        when(mockConfigurationService.getSsmParameter(MAX_JWT_TTL)).thenReturn("1000");
    }

    @Test
    void shouldReturnCredentialsOnSuccessfulDcsCredentialRequest()
            throws JsonProcessingException, ParseException, JOSEException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        accessToken.getValue(),
                        TEST_RESOURCE_ID,
                        Instant.now().plusSeconds(3600).toString(),
                        UUID.randomUUID().toString());
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getAccessTokenItem(accessToken.getValue()))
                .thenReturn(accessTokenItem);
        when(mockDcsPassportCheckService.getDcsPassportCheck(anyString()))
                .thenReturn(passportCheckDao);
        when(mockConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("test-issuer");
        when(mockConfigurationService.getClientIssuer(clientId))
                .thenReturn("https://example.com/issuer");
        mockConfigurationServiceCalls();

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);

        SignedJWT signedJWT = SignedJWT.parse(response.getBody());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        assertEquals(200, response.getStatusCode());
        assertEquals(6, claimsSet.size());
        assertEquals("https://example.com/issuer", claimsSet.get("aud").asText());

        verify(mockAccessTokenService).revokeAccessToken(accessTokenItem.getAccessToken());

        JsonNode vcNode = claimsSet.get("vc");
        VerifiableCredential verifiableCredential =
                objectMapper.convertValue(vcNode, VerifiableCredential.class);
        List<NameParts> nameParts =
                verifiableCredential.getCredentialSubject().getName().get(0).getNameParts();

        assertEquals(passportCheckDao.getUserId(), claimsSet.get("sub").asText());

        assertEquals(
                List.of(VERIFIABLE_CREDENTIAL_TYPE, IDENTITY_CHECK_CREDENTIAL_TYPE),
                verifiableCredential.getType());

        assertTrue(
                nameParts.stream()
                        .anyMatch(
                                o ->
                                        isType(NamePartType.FAMILY_NAME)
                                                .and(
                                                        hasValue(
                                                                passportCheckDao
                                                                        .getDcsPayload()
                                                                        .getSurname()))
                                                .test(o)));
        assertTrue(
                nameParts.stream()
                        .anyMatch(
                                o ->
                                        isType(NamePartType.GIVEN_NAME)
                                                .and(
                                                        hasValue(
                                                                passportCheckDao
                                                                        .getDcsPayload()
                                                                        .getForenames()
                                                                        .get(0)))
                                                .test(o)));

        assertEquals(
                passportCheckDao.getDcsPayload().getDateOfBirth().toString(),
                verifiableCredential.getCredentialSubject().getBirthDate().get(0).getValue());

        assertEquals(
                passportCheckDao.getDcsPayload().getPassportNumber(),
                verifiableCredential
                        .getCredentialSubject()
                        .getPassport()
                        .get(0)
                        .getDocumentNumber());

        assertEquals(
                passportCheckDao.getDcsPayload().getExpiryDate().toString(),
                verifiableCredential.getCredentialSubject().getPassport().get(0).getExpiryDate());

        assertEquals(
                passportCheckDao.getEvidence().getTxn(),
                verifiableCredential.getEvidence().get(0).getTxn());

        assertEquals(
                passportCheckDao.getEvidence().getType(),
                verifiableCredential.getEvidence().get(0).getType());

        assertEquals(
                passportCheckDao.getEvidence().getStrengthScore(),
                verifiableCredential.getEvidence().get(0).getStrengthScore());
        assertEquals(
                passportCheckDao.getEvidence().getValidityScore(),
                verifiableCredential.getEvidence().get(0).getValidityScore());

        assertNull(verifiableCredential.getEvidence().get(0).getCi());

        ECDSAVerifier ecVerifier = new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK_1));
        assertTrue(signedJWT.verify(ecVerifier));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsNull() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", null);
        event.setHeaders(headers);
        setRequestBodyAsPlainJWT(event);

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissingBearerPrefix() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", "11111111");
        event.setHeaders(headers);
        setRequestBodyAsPlainJWT(event);

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(
                BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.INVALID_REQUEST.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        setRequestBodyAsPlainJWT(event);

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenInvalidAccessTokenProvided() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);
        setRequestBodyAsPlainJWT(event);

        when(mockAccessTokenService.getAccessTokenItem(accessToken.getValue())).thenReturn(null);

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - The supplied access token was not found in the database")
                        .getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenAccessTokenHasBeenRevoked() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);
        setRequestBodyAsPlainJWT(event);

        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        accessToken.getValue(),
                        TEST_RESOURCE_ID,
                        Instant.now().plusSeconds(60).toString(),
                        UUID.randomUUID().toString());
        accessTokenItem.setRevokedAtDateTime(Instant.now().toString());

        when(mockAccessTokenService.getAccessTokenItem(accessToken.getValue()))
                .thenReturn(accessTokenItem);

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has been revoked")
                        .getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenExpiredAccessTokenProvided() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        accessToken.getValue(),
                        TEST_RESOURCE_ID,
                        Instant.now().minusSeconds(5).toString(),
                        UUID.randomUUID().toString());
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);
        setRequestBodyAsPlainJWT(event);

        when(mockAccessTokenService.getAccessTokenItem(accessToken.getValue()))
                .thenReturn(accessTokenItem);

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .getDescription(),
                responseBody.get("error_description"));
    }

    void shouldReturnErrorResponseWhenAccessTokenCannotBeRevoked() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setResourceId(TEST_RESOURCE_ID);
        accessTokenItem.setAccessToken(accessToken.toAuthorizationHeader());

        when(mockAccessTokenService.getAccessTokenItem(anyString())).thenReturn(accessTokenItem);
        when(mockDcsPassportCheckService.getDcsPassportCheck(anyString()))
                .thenReturn(passportCheckDao);
        when(mockConfigurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                .thenReturn("test-issuer");
        when(mockConfigurationService.getClientIssuer(clientId))
                .thenReturn("https://example.com/issuer");

        doThrow(new IllegalArgumentException("Test error"))
                .when(mockAccessTokenService)
                .revokeAccessToken(anyString());

        APIGatewayProxyResponseEvent response =
                issueCredentialHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_REVOKE_ACCESS_TOKEN.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_REVOKE_ACCESS_TOKEN.getMessage(),
                responseBody.get("message"));
    }

    private static ECPrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY_1)));
    }

    private static Predicate<NameParts> isType(NamePartType namePartType) {
        return row -> row.getType().equals(namePartType.getName());
    }

    private static Predicate<NameParts> hasValue(String value) {
        return row -> row.getValue().equals(value);
    }

    private void setRequestBodyAsPlainJWT(APIGatewayProxyRequestEvent event) {
        String requestJWT =
                new PlainJWT(
                                new JWTClaimsSet.Builder()
                                        .claim(JWTClaimNames.SUBJECT, SUBJECT)
                                        .build())
                        .serialize();

        event.setBody(requestJWT);
    }
}
