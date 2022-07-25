package uk.gov.di.ipv.cri.passport.library.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.ssm.model.SsmException;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.exceptions.JarValidationException;
import uk.gov.di.ipv.cri.passport.library.exceptions.RecoverableJarValidationException;
import uk.gov.di.ipv.cri.passport.library.helpers.JwtHelper;
import uk.gov.di.ipv.cri.passport.library.service.KmsRsaDecrypter;

import java.net.URI;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.PASSPORT_CRI_CLIENT_AUDIENCE;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.PASSPORT_CRI_CLIENT_AUTH_MAX_TTL;

public class JarValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(JarValidator.class);
    private static final String REDIRECT_URI_CLAIM = "redirect_uri";
    public static final String CLIENT_ID = "client_id";
    private static final String STATE = "state";

    private final KmsRsaDecrypter kmsRsaDecrypter;
    private final ConfigurationService configurationService;

    public JarValidator(
            KmsRsaDecrypter kmsRsaDecrypter, ConfigurationService configurationService) {
        this.kmsRsaDecrypter = kmsRsaDecrypter;
        this.configurationService = configurationService;
    }

    public SignedJWT decryptJWE(JWEObject jweObject) throws JarValidationException {
        try {
            jweObject.decrypt(kmsRsaDecrypter);

            return jweObject.getPayload().toSignedJWT();
        } catch (JOSEException e) {
            LOGGER.error("Failed to decrypt the JWE");
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to decrypt the contents of the JAR"));
        }
    }

    public JWTClaimsSet validateRequestJwt(SignedJWT signedJWT, String clientId)
            throws JarValidationException, ParseException {
        validateQueryParamClientIdIsRecognised(clientId);
        validateJWTHeader(signedJWT);
        validateSignature(signedJWT, clientId);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        validateQueryParamClientIdMatchesRequestObjectClientId(clientId, claimsSet);
        URI redirectUri = validateRedirectUri(claimsSet, clientId);

        try {
            return getValidatedClaimSet(signedJWT, clientId);
        } catch (JarValidationException e) {
            String state = claimsSet.getStringClaim(STATE);
            throw new RecoverableJarValidationException(
                    e.getErrorObject(), redirectUri.toString(), state);
        }
    }

    private void validateQueryParamClientIdIsRecognised(String clientId)
            throws JarValidationException {
        try {
            configurationService.getClientIssuer(clientId);
        } catch (SsmException e) {
            LOGGER.error("Unknown client id provided {}", clientId);
            throw new JarValidationException(
                    OAuth2Error.INVALID_CLIENT.setDescription("Unknown client id was provided"));
        }
    }

    private void validateQueryParamClientIdMatchesRequestObjectClientId(
            String queryParamClientId, JWTClaimsSet claimsSet) throws JarValidationException {
        String requestObjectClientId;
        try {
            requestObjectClientId = claimsSet.getStringClaim(CLIENT_ID);
        } catch (ParseException e) {
            LOGGER.error("client_id not found in claims set: '{}'", e.getMessage());
            throw new JarValidationException(
                    OAuth2Error.INVALID_CLIENT.setDescription(
                            "Client ID could not be parsed from claims set"));
        }
        if (!queryParamClientId.equals(requestObjectClientId)) {
            LOGGER.error("Query param client ID does not match JAR request object client ID");
            throw new JarValidationException(
                    OAuth2Error.INVALID_CLIENT.setDescription(
                            "Query param client ID does not match JAR request object client ID"));
        }
    }

    private void validateJWTHeader(SignedJWT signedJWT) throws JarValidationException {
        JWSAlgorithm jwtAlgorithm = signedJWT.getHeader().getAlgorithm();
        if (jwtAlgorithm != JWSAlgorithm.ES256) {
            LOGGER.error(
                    "jwt signing algorithm {} does not match expected signing algorithm ES256",
                    jwtAlgorithm);
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Signing algorithm used does not match required algorithm"));
        }
    }

    private void validateSignature(SignedJWT signedJWT, String clientId)
            throws JarValidationException {
        try {
            SignedJWT concatSignatureJwt;
            if (JwtHelper.signatureIsDerFormat(signedJWT)) {
                concatSignatureJwt = JwtHelper.transcodeSignature(signedJWT);
            } else {
                concatSignatureJwt = signedJWT;
            }
            boolean valid =
                    concatSignatureJwt.verify(
                            new ECDSAVerifier(
                                    configurationService.getClientSigningPublicJwk(clientId)));

            if (!valid) {
                LOGGER.error("JWT signature validation failed");
                throw new JarValidationException(
                        OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                                "JWT signature validation failed"));
            }
        } catch (JOSEException | ParseException e) {
            LOGGER.error("Failed to parse JWT when attempting signature validation");
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT when attempting signature validation"));
        }
    }

    private JWTClaimsSet getValidatedClaimSet(SignedJWT signedJWT, String clientId)
            throws JarValidationException {

        String criAudience = configurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUDIENCE);
        String clientIssuer = configurationService.getClientIssuer(clientId);

        DefaultJWTClaimsVerifier<?> verifier =
                new DefaultJWTClaimsVerifier<>(
                        criAudience,
                        new JWTClaimsSet.Builder()
                                .issuer(clientIssuer)
                                .claim("response_type", "code")
                                .build(),
                        Set.of(
                                JWTClaimNames.EXPIRATION_TIME,
                                JWTClaimNames.NOT_BEFORE,
                                JWTClaimNames.ISSUED_AT,
                                JWTClaimNames.SUBJECT));

        try {
            verifier.verify(signedJWT.getJWTClaimsSet(), null);

            validateMaxAllowedJarTtl(signedJWT.getJWTClaimsSet());

            return signedJWT.getJWTClaimsSet();
        } catch (BadJWTException | ParseException e) {
            LOGGER.error("Claim set validation failed");
            throw new JarValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription(e.getMessage()));
        }
    }

    private void validateMaxAllowedJarTtl(JWTClaimsSet claimsSet) throws JarValidationException {
        String maxAllowedTtl =
                configurationService.getSsmParameter(PASSPORT_CRI_CLIENT_AUTH_MAX_TTL);
        LocalDateTime maximumExpirationTime =
                LocalDateTime.now().plusSeconds(Long.parseLong(maxAllowedTtl));
        LocalDateTime expirationTime =
                LocalDateTime.ofInstant(claimsSet.getExpirationTime().toInstant(), ZoneOffset.UTC);

        if (expirationTime.isAfter(maximumExpirationTime)) {
            LOGGER.error("Client JWT expiry date is too far in the future");
            throw new JarValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription(
                            "The client JWT expiry date has surpassed the maximum allowed ttl value"));
        }
    }

    private URI validateRedirectUri(JWTClaimsSet claimsSet, String clientId)
            throws JarValidationException {
        try {
            URI redirectUri = claimsSet.getURIClaim(REDIRECT_URI_CLAIM);
            List<String> allowedRedirectUris = configurationService.getClientRedirectUrls(clientId);

            if (!allowedRedirectUris.contains(redirectUri.toString())) {
                LOGGER.error(
                        "Invalid redirect_uri claim ({}) provided for client: {}",
                        redirectUri,
                        clientId);
                throw new JarValidationException(
                        OAuth2Error.INVALID_GRANT.setDescription(
                                "Invalid redirct_uri claim provided for configured client"));
            }

            return redirectUri;
        } catch (ParseException e) {
            LOGGER.error(
                    "Failed to parse JWT claim set in order to access to the redirect_uri claim");
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT claim set in order to access redirect_uri claim"));
        }
    }
}
