package uk.gov.di.ipv.cri.passport.checkpassport;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEvent;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventUser;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditExtensions;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditRestricted;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditRestrictedVcCredentialSubject;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.AuthParams;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.ContraIndicators;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.CredentialSubject;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredential;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.exceptions.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthHttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.library.service.PassportService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.MAXIMUM_ATTEMPT_COUNT;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.VERIFIABLE_CREDENTIAL_ISSUER;

public class CheckPassportHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private static final int MAX_PASSPORT_GPG45_STRENGTH_VALUE = 4;
    private static final int MAX_PASSPORT_GPG45_VALIDITY_VALUE = 2;
    private static final int MIN_PASSPORT_GPG45_VALUE = 0;

    public static final String CLIENT_ID_PARAM = "client_id";
    public static final String REDIRECT_URI_PARAM = "redirect_uri";
    public static final String RESPONSE_TYPE_PARAM = "response_type";
    public static final String STATE_PARAM = "state";

    public static final String RESULT = "result";
    public static final String RESULT_FINISH = "finish";
    public static final String RESULT_RETRY = "retry";

    private final PassportService passportService;
    private final ConfigurationService configurationService;
    private final DcsCryptographyService dcsCryptographyService;
    private final AuditService auditService;

    private final PassportSessionService passportSessionService;

    public CheckPassportHandler(
            PassportService passportService,
            ConfigurationService configurationService,
            DcsCryptographyService dcsCryptographyService,
            AuditService auditService,
            PassportSessionService passportSessionService) {
        this.passportService = passportService;
        this.configurationService = configurationService;
        this.dcsCryptographyService = dcsCryptographyService;
        this.auditService = auditService;
        this.passportSessionService = passportSessionService;
    }

    public CheckPassportHandler()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.configurationService = new ConfigurationService();
        this.passportService = new PassportService(configurationService);
        this.dcsCryptographyService = new DcsCryptographyService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.passportSessionService = new PassportSessionService(configurationService);
    }

    @Override
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String passportSessionId = RequestHelper.getPassportSessionId(input);

            PassportSessionItem passportSessionItem =
                    passportSessionService.getPassportSession(passportSessionId);

            if (passportSessionItem == null) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST,
                        new ErrorObject(
                                        OAuth2Error.SERVER_ERROR_CODE,
                                        ErrorResponse.PASSPORT_SESSION_NOT_FOUND.getMessage())
                                .toJSONObject());
            }

            passportSessionService.incrementAttemptCount(passportSessionId);

            String userId = passportSessionItem.getUserId();
            var authParams = passportSessionItem.getAuthParams();

            AuthorizationRequest authorizationRequest =
                    AuthorizationRequest.parse(getAuthParamsAsMap(authParams));

            LogHelper.attachClientIdToLogs(authorizationRequest.getClientID().getValue());

            DcsPayload dcsPayload = parsePassportFormRequest(input.getBody());
            JWSObject preparedDcsPayload = preparePayload(dcsPayload);

            auditService.sendAuditEvent(
                    createAuditEventRequestSent(
                            userId, dcsPayload, authorizationRequest.getClientID().getValue()));

            DcsSignedEncryptedResponse dcsResponse = doPassportCheck(preparedDcsPayload);

            auditService.sendAuditEvent(createAuditEventResponseReceived());

            DcsResponse unwrappedDcsResponse = unwrapDcsResponse(dcsResponse);

            validateDcsResponse(unwrappedDcsResponse);

            PassportCheckDao passportCheckDao =
                    new PassportCheckDao(
                            UUID.randomUUID().toString(),
                            dcsPayload,
                            generateGpg45Score(unwrappedDcsResponse),
                            userId,
                            authorizationRequest.getClientID().getValue());
            passportService.persistDcsResponse(passportCheckDao);

            auditService.sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_END);

            passportSessionService.setLatestDcsResponseResourceId(
                    passportSessionId, passportCheckDao.getResourceId());

            return validateResponseAndAttemptCount(passportSessionId, unwrappedDcsResponse);

        } catch (OAuthHttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(),
                    new ErrorObject(OAuth2Error.SERVER_ERROR_CODE, e.getErrorReason())
                            .toJSONObject());
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), e.getErrorResponse());
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    new ErrorObject(
                                    OAuth2Error.SERVER_ERROR_CODE,
                                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS
                                            .getMessage())
                            .toJSONObject());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    new ErrorObject(
                                    OAuth2Error.SERVER_ERROR_CODE,
                                    ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE
                                            .getMessage())
                            .toJSONObject());
        }
    }

    private APIGatewayProxyResponseEvent validateResponseAndAttemptCount(
            String passportSessionId, DcsResponse unwrappedDcsResponse) {

        int attemptCount =
                passportSessionService.getPassportSession(passportSessionId).getAttemptCount();

        if (unwrappedDcsResponse.isValid()
                || attemptCount
                        >= Integer.parseInt(
                                configurationService.getSsmParameter(MAXIMUM_ATTEMPT_COUNT))) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, Map.of(RESULT, RESULT_FINISH));
        }

        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatus.SC_OK, Map.of(RESULT, RESULT_RETRY));
    }

    private AuditEvent createAuditEventRequestSent(
            String userId, DcsPayload dcsPayload, String clientId) {

        PassportCheckDao passportCheckDao =
                new PassportCheckDao(
                        UUID.randomUUID().toString(), dcsPayload, null, userId, clientId);

        VerifiableCredential vc = VerifiableCredential.fromPassportCheckDao(passportCheckDao);

        CredentialSubject credentialSubject = vc.getCredentialSubject();
        String componentId = configurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER);
        AuditEventTypes eventType = AuditEventTypes.IPV_PASSPORT_CRI_REQUEST_SENT;
        AuditEventUser user = new AuditEventUser(userId, null);
        AuditRestricted restricted =
                new AuditRestrictedVcCredentialSubject(
                        credentialSubject.getName(),
                        credentialSubject.getBirthDate(),
                        credentialSubject.getPassport());
        AuditExtensions extensions =
                new AuditExtensionsVcEvidence(
                        configurationService.getSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER), null);
        return new AuditEvent(eventType, componentId, user, restricted, extensions);
    }

    private AuditEvent createAuditEventResponseReceived() {
        return new AuditEvent(
                AuditEventTypes.IPV_PASSPORT_CRI_RESPONSE_RECEIVED, null, null, null, null);
    }

    private void validateDcsResponse(DcsResponse dcsResponse)
            throws OAuthHttpResponseExceptionWithErrorBody {
        if (dcsResponse.isError()) {
            String errorMessage = dcsResponse.getErrorMessage().toString();
            LOGGER.error("DCS encountered an error: {}", errorMessage);
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.DCS_RETURNED_AN_ERROR);
        }
    }

    private Evidence generateGpg45Score(DcsResponse dcsResponse) {
        return new Evidence(
                UUID.randomUUID().toString(),
                MAX_PASSPORT_GPG45_STRENGTH_VALUE,
                calculateValidity(dcsResponse),
                calculateContraIndicators(dcsResponse));
    }

    private DcsPayload parsePassportFormRequest(String input)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Parsing passport form data into payload for DCS");
        try {
            return objectMapper.readValue(input, DcsPayload.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(("Failed to parse payload from input: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
    }

    private JWSObject preparePayload(DcsPayload dcsPayload)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Preparing payload for DCS");
        try {
            return dcsCryptographyService.preparePayload(dcsPayload);
        } catch (CertificateException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException
                | JsonProcessingException e) {
            LOGGER.error(("Failed to prepare payload for DCS: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PREPARE_DCS_PAYLOAD);
        }
    }

    private DcsSignedEncryptedResponse doPassportCheck(JWSObject preparedPayload)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Sending passport check to DCS");
        try {
            return passportService.dcsPassportCheck(preparedPayload);
        } catch (IOException | EmptyDcsResponseException e) {
            LOGGER.error(("Passport check with DCS failed: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.ERROR_CONTACTING_DCS);
        }
    }

    private DcsResponse unwrapDcsResponse(DcsSignedEncryptedResponse response)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Unwrapping DCS response");
        try {
            return dcsCryptographyService.unwrapDcsResponse(response);
        } catch (CertificateException
                | java.text.ParseException
                | JOSEException
                | IpvCryptoException e) {
            LOGGER.error(("Failed to unwrap response from DCS: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
        }
    }

    private int calculateValidity(DcsResponse dcsResponse) {
        return dcsResponse.isValid() ? MAX_PASSPORT_GPG45_VALIDITY_VALUE : MIN_PASSPORT_GPG45_VALUE;
    }

    private List<ContraIndicators> calculateContraIndicators(DcsResponse dcsResponse) {
        return dcsResponse.isValid() ? null : List.of(ContraIndicators.D02);
    }

    private Map<String, List<String>> getAuthParamsAsMap(AuthParams params) {
        if (params != null) {
            Map<String, List<String>> authParams = new HashMap<>();
            authParams.put(
                    RESPONSE_TYPE_PARAM, Collections.singletonList(params.getResponseType()));
            authParams.put(CLIENT_ID_PARAM, Collections.singletonList(params.getClientId()));
            authParams.put(REDIRECT_URI_PARAM, Collections.singletonList(params.getRedirectUri()));
            authParams.put(STATE_PARAM, Collections.singletonList(params.getState()));

            return authParams;
        }

        return Collections.emptyMap();
    }
}
