package uk.gov.di.ipv.cri.passport.issuecredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEvent;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventUser;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditExtensions;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditRestricted;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditRestrictedVcCredentialSubject;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.CredentialSubject;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredential;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.JwtHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.KmsSigner;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.DcsPassportCheckService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.time.Instant;
import java.util.Date;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.MAX_JWT_TTL;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.VERIFIABLE_CREDENTIAL_ISSUER;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VC_CLAIM;

public class IssueCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    private final DcsPassportCheckService dcsPassportCheckService;
    private final AccessTokenService accessTokenService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final PassportSessionService passportSessionService;
    private final JWSSigner kmsSigner;

    public IssueCredentialHandler(
            DcsPassportCheckService dcsPassportCheckService,
            AccessTokenService accessTokenService,
            ConfigurationService configurationService,
            AuditService auditService,
            PassportSessionService passportSessionService,
            JWSSigner kmsSigner) {
        this.configurationService = configurationService;
        this.dcsPassportCheckService = dcsPassportCheckService;
        this.accessTokenService = accessTokenService;
        this.auditService = auditService;
        this.passportSessionService = passportSessionService;
        this.kmsSigner = kmsSigner;
    }

    @ExcludeFromGeneratedCoverageReport
    public IssueCredentialHandler() {
        this.configurationService = new ConfigurationService();
        this.dcsPassportCheckService = new DcsPassportCheckService(configurationService);
        this.accessTokenService = new AccessTokenService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.passportSessionService = new PassportSessionService(configurationService);
        this.kmsSigner =
                new KmsSigner(
                        configurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID));
    }

    @Override
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            AccessToken accessToken =
                    AccessToken.parse(
                            RequestHelper.getHeaderByKey(
                                    input.getHeaders(), AUTHORIZATION_HEADER_KEY),
                            AccessTokenType.BEARER);

            AccessTokenItem accessTokenItem =
                    accessTokenService.getAccessTokenItem(accessToken.getValue());

            if (accessTokenItem == null) {
                LOGGER.error(
                        "User credential could not be retrieved. The supplied access token was not found in the database.");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                        OAuth2Error.ACCESS_DENIED
                                .appendDescription(
                                        " - The supplied access token was not found in the database")
                                .toJSONObject());
            }

            String accessTokenExpiryDateTime = accessTokenItem.getAccessTokenExpiryDateTime();
            if (Instant.now().isAfter(Instant.parse(accessTokenExpiryDateTime))) {
                LOGGER.error(
                        "User credential could not be retrieved. The supplied access token expired at: {}",
                        accessTokenExpiryDateTime);
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                        OAuth2Error.ACCESS_DENIED
                                .appendDescription(" - The supplied access token has expired")
                                .toJSONObject());
            }

            if (StringUtils.isNotBlank(accessTokenItem.getRevokedAtDateTime())) {
                LOGGER.error(
                        "User credential could not be retrieved. The supplied access token has been revoked at: {}",
                        accessTokenItem.getRevokedAtDateTime());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                        OAuth2Error.ACCESS_DENIED
                                .appendDescription(" - The supplied access token has been revoked")
                                .toJSONObject());
            }

            accessTokenService.revokeAccessToken(accessTokenItem.getAccessToken());

            PassportCheckDao passportCheck =
                    dcsPassportCheckService.getDcsPassportCheck(
                            getPassportCheckResourceId(accessTokenItem));
            LogHelper.attachClientIdToLogs(passportCheck.getClientId());

            VerifiableCredential verifiableCredential =
                    VerifiableCredential.fromPassportCheckDao(passportCheck);

            SignedJWT signedJWT =
                    generateAndSignVerifiableCredentialJwt(verifiableCredential, passportCheck);

            auditService.sendAuditEvent(createAuditEvent(verifiableCredential, passportCheck));

            return ApiGatewayResponseGenerator.proxyJwtResponse(
                    HttpStatus.SC_OK, signedJWT.serialize());
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (JOSEException e) {
            LOGGER.error("Failed to sign verifiable credential: '{}'", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                    OAuth2Error.SERVER_ERROR
                            .appendDescription(" " + e.getMessage())
                            .toJSONObject());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE);
        } catch (IllegalArgumentException e) {
            LOGGER.error("Failed to revoke access token after use because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_REVOKE_ACCESS_TOKEN);
        }
    }

    private String getPassportCheckResourceId(AccessTokenItem accessTokenItem) {
        return StringUtils.isBlank(accessTokenItem.getResourceId())
                ? passportSessionService
                        .getPassportSession(accessTokenItem.getPassportSessionId())
                        .getLatestDcsResponseResourceId()
                : accessTokenItem.getResourceId();
    }

    private AuditEvent createAuditEvent(VerifiableCredential vc, PassportCheckDao passportCheck) {
        CredentialSubject credentialSubject = vc.getCredentialSubject();
        String componentId = configurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER);
        AuditEventTypes eventType = AuditEventTypes.IPV_PASSPORT_CRI_VC_ISSUED;
        AuditEventUser user = new AuditEventUser(passportCheck.getUserId(), null);
        AuditRestricted restricted =
                new AuditRestrictedVcCredentialSubject(
                        credentialSubject.getName(),
                        credentialSubject.getBirthDate(),
                        credentialSubject.getPassport());
        AuditExtensions extensions =
                new AuditExtensionsVcEvidence(
                        configurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER),
                        vc.getEvidence());
        return new AuditEvent(eventType, componentId, user, restricted, extensions);
    }

    private SignedJWT generateAndSignVerifiableCredentialJwt(
            VerifiableCredential verifiableCredential, PassportCheckDao passportCheck)
            throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject(passportCheck.getUserId())
                        .issuer(configurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER))
                        .audience(configurationService.getClientIssuer(passportCheck.getClientId()))
                        .notBeforeTime(new Date(now.toEpochMilli()))
                        .expirationTime(
                                new Date(
                                        now.plusSeconds(
                                                        Long.parseLong(
                                                                configurationService
                                                                        .getSsmParameter(
                                                                                MAX_JWT_TTL)))
                                                .toEpochMilli()))
                        .claim(VC_CLAIM, verifiableCredential)
                        .build();

        return JwtHelper.createSignedJwtFromClaimSet(claimsSet, kmsSigner);
    }
}
