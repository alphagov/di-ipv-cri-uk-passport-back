package uk.gov.di.ipv.cri.passport.accesstoken.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.accesstoken.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.cri.passport.library.service.ClientAuthJwtIdService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.PASSPORT_CRI_CLIENT_AUDIENCE;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.PASSPORT_CRI_CLIENT_AUTH_MAX_TTL;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PRIVATE_KEY_1;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PUBLIC_JWK_1;

@ExtendWith(MockitoExtension.class)
class TokenRequestValidatorTest {

    private TokenRequestValidator validator;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private ClientAuthJwtIdService mockClientAuthJwtIdService;

    private final String clientId = "testClientId";
    private final String audience = "https://audience.example.com";

    private final String jti = "test-jti";

    @BeforeEach
    void setUp() {
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUDIENCE))
                .thenReturn(audience);
        validator = new TokenRequestValidator(mockConfigurationService, mockClientAuthJwtIdService);
    }

    @Test
    void shouldNotThrowForValidJwt() throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk(clientId))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUTH_MAX_TTL))
                .thenReturn("2400");

        var validQueryParams =
                getValidQueryParams(generateClientAssertion(getValidClaimsSetValues()));
        assertDoesNotThrow(() -> validator.authenticateClient(queryMapToString(validQueryParams)));
    }

    @Test
    void shouldNotThrowForValidJwtWithDerSignature() throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk(clientId))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUTH_MAX_TTL))
                .thenReturn("2400");

        SignedJWT signedJWT = SignedJWT.parse(generateClientAssertion(getValidClaimsSetValues()));
        Base64URL derSignature =
                Base64URL.encode(ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode()));
        Base64URL[] jwtParts = signedJWT.getParsedParts();
        SignedJWT derSignatureJwt =
                SignedJWT.parse(String.format("%s.%s.%s", jwtParts[0], jwtParts[1], derSignature));

        var validQueryParams = getValidQueryParams(derSignatureJwt.serialize());
        assertDoesNotThrow(() -> validator.authenticateClient(queryMapToString(validQueryParams)));
    }

    @Test
    void shouldThrowIfInvalidSignature() throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk(clientId))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));

        var invalidSignatureQueryParams =
                new HashMap<>(
                        getValidQueryParams(generateClientAssertion(getValidClaimsSetValues())));
        String invalidSignatureJwt = invalidSignatureQueryParams.get("client_assertion");
        invalidSignatureQueryParams.put(
                "client_assertion",
                invalidSignatureJwt.substring(0, invalidSignatureJwt.length() - 4) + "nope");

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(invalidSignatureQueryParams)));

        assertTrue(exception.getMessage().contains("InvalidClientException: Bad JWT signature"));
    }

    @Test
    void shouldThrowIfClaimsSetIssuerAndSubjectAreNotTheSame() throws Exception {
        var differentIssuerAndSubjectClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        differentIssuerAndSubjectClaimsSetValues.put(
                JWTClaimNames.ISSUER, "NOT_THE_SAME_AS_SUBJECT");
        var differentIssuerAndSubjectQueryParams =
                getValidQueryParams(
                        generateClientAssertion(differentIssuerAndSubjectClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(differentIssuerAndSubjectQueryParams)));

        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "Issuer and subject in client JWT assertion must designate the same client identifier"));
    }

    @Test
    void shouldThrowIfWrongAudience()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        var wrongAudienceClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        wrongAudienceClaimsSetValues.put(
                JWTClaimNames.AUDIENCE, "NOT_THE_AUDIENCE_YOU_ARE_LOOKING_FOR");
        var wrongAudienceQueryParams =
                getValidQueryParams(generateClientAssertion(wrongAudienceClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(wrongAudienceQueryParams)));

        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "Invalid JWT audience claim, expected [https://audience.example.com]"));
    }

    @Test
    void shouldThrowIfClaimsSetHasExpired()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        var expiredClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        expiredClaimsSetValues.put(
                JWTClaimNames.EXPIRATION_TIME,
                new Date(new Date().getTime() - 61000).getTime() / 1000);
        var expiredQueryParams =
                getValidQueryParams(generateClientAssertion(expiredClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () -> validator.authenticateClient(queryMapToString(expiredQueryParams)));

        assertTrue(exception.getMessage().contains("Expired JWT"));
    }

    @Test
    void shouldFailWhenCLientJWTContainsExpiryClaimTooFarInFuture() throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk(clientId))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUTH_MAX_TTL))
                .thenReturn("2400");
        var expiredClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        expiredClaimsSetValues.put(
                JWTClaimNames.EXPIRATION_TIME,
                new Date(new Date().getTime() + 9999999).getTime() / 1000);
        var expiredQueryParams =
                getValidQueryParams(generateClientAssertion(expiredClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () -> validator.authenticateClient(queryMapToString(expiredQueryParams)));
        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "The client JWT expiry date has surpassed the maximum allowed ttl value"));
    }

    @Test
    void shouldThrowIfMissingClientAssertionParam() {
        String invalidClientId = "invalid-client";

        var missingClientAssertionParams = getValidQueryParamsWithoutClientAuth(invalidClientId);

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(missingClientAssertionParams)));

        assertEquals("Missing client_assertion_type parameter", exception.getCause().getMessage());
    }

    @Test
    void shouldThrowIfMissingClientAssertionAndClientIdParams() {
        var missingClientIdParams = getParamsWithoutClientAuthOrClientId();

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(missingClientIdParams)));

        assertEquals("Missing client_assertion_type parameter", exception.getCause().getMessage());
    }

    @Test
    void shouldThrowIfMissingJwtId() throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk(clientId))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUTH_MAX_TTL))
                .thenReturn("2400");
        Map<String, Object> claimsSetValues = getClaimsSetValuesMissingJwtId();
        String clientAssertion = generateClientAssertion(claimsSetValues);

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(getValidQueryParams(clientAssertion))));

        assertEquals("The client auth JWT id (jti) is missing", exception.getCause().getMessage());
    }

    @Test
    void shouldThrowIfJwtIdHasAlreadyBeenUsed() throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk(clientId))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUTH_MAX_TTL))
                .thenReturn("2400");
        Map<String, Object> claimsSetValues = getValidClaimsSetValues();
        String clientAssertion = generateClientAssertion(claimsSetValues);

        ClientAuthJwtIdItem clientAuthJwtIdItem =
                new ClientAuthJwtIdItem(jti, Instant.now().toString());
        when(mockClientAuthJwtIdService.getClientAuthJwtIdItem(jti))
                .thenReturn(clientAuthJwtIdItem);

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(getValidQueryParams(clientAssertion))));

        assertEquals(
                "The client auth JWT id (jti) has already been used",
                exception.getCause().getMessage());
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        java.util.Base64.getDecoder().decode(EC_PRIVATE_KEY_1)));
    }

    private Map<String, String> getValidQueryParams(String clientAssertion) {
        return Map.of(
                "client_assertion", clientAssertion,
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "code", ResponseType.Value.CODE.getValue(),
                "grant_type", "authorization_code",
                "redirect_uri", "https://test-client.example.com/callback");
    }

    private Map<String, String> getValidQueryParamsWithoutClientAuth(String clientId) {
        return Map.of(
                "client_id",
                clientId,
                "code",
                ResponseType.Value.CODE.getValue(),
                "grant_type",
                "authorization_code",
                "redirect_uri",
                "https://test-client.example.com/callback");
    }

    private Map<String, String> getParamsWithoutClientAuthOrClientId() {
        return Map.of(
                "code", ResponseType.Value.CODE.getValue(),
                "grant_type", "authorization_code",
                "redirect_uri", "https://test-client.example.com/callback");
    }

    private String queryMapToString(Map<String, String> queryParams) {
        StringBuilder sb = new StringBuilder();

        for (Map.Entry<String, String> param : queryParams.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(
                    String.format(
                            "%s=%s",
                            URLEncoder.encode(param.getKey(), StandardCharsets.UTF_8),
                            URLEncoder.encode(param.getValue(), StandardCharsets.UTF_8)));
        }
        return sb.toString();
    }

    private Map<String, Object> getValidClaimsSetValues() {
        return Map.of(
                JWTClaimNames.ISSUER,
                clientId,
                JWTClaimNames.SUBJECT,
                clientId,
                JWTClaimNames.AUDIENCE,
                audience,
                JWTClaimNames.EXPIRATION_TIME,
                fifteenMinutesFromNow(),
                JWTClaimNames.JWT_ID,
                jti);
    }

    private Map<String, Object> getClaimsSetValuesMissingJwtId() {
        return Map.of(
                JWTClaimNames.ISSUER,
                clientId,
                JWTClaimNames.SUBJECT,
                clientId,
                JWTClaimNames.AUDIENCE,
                audience,
                JWTClaimNames.EXPIRATION_TIME,
                fifteenMinutesFromNow());
    }

    private static long fifteenMinutesFromNow() {
        return OffsetDateTime.now().plusSeconds(15 * 60).toEpochSecond();
    }

    private String generateClientAssertion(Map<String, Object> claimsSetValues)
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());

        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        generateClaimsSet(claimsSetValues));
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private JWTClaimsSet generateClaimsSet(Map<String, Object> claimsSetValues) {
        return new JWTClaimsSet.Builder()
                .claim(JWTClaimNames.ISSUER, claimsSetValues.get(JWTClaimNames.ISSUER))
                .claim(JWTClaimNames.SUBJECT, claimsSetValues.get(JWTClaimNames.SUBJECT))
                .claim(JWTClaimNames.AUDIENCE, claimsSetValues.get(JWTClaimNames.AUDIENCE))
                .claim(JWTClaimNames.JWT_ID, claimsSetValues.get(JWTClaimNames.JWT_ID))
                .claim(
                        JWTClaimNames.EXPIRATION_TIME,
                        claimsSetValues.get(JWTClaimNames.EXPIRATION_TIME))
                .build();
    }
}
