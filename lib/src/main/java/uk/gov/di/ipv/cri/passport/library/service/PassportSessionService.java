package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.AuthParams;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;

import java.text.ParseException;
import java.time.Instant;

import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.PASSPORT_BACK_SESSIONS_TABLE_NAME;

public class PassportSessionService {
    private static final String RESPONSE_TYPE = "response_type";
    private static final String CLIENT_ID = "client_id";
    private static final String STATE = "state";
    private static final String REDIRECT_URI = "redirect_uri";

    private final DataStore<PassportSessionItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public PassportSessionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                PASSPORT_BACK_SESSIONS_TABLE_NAME),
                        PassportSessionItem.class,
                        DataStore.getClient(
                                this.configurationService.getDynamoDbEndpointOverride()),
                        this.configurationService);
    }

    public PassportSessionService(
            DataStore<PassportSessionItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public PassportSessionItem getPassportSession(String passportSessionId) {
        return dataStore.getItem(passportSessionId);
    }

    public String generatePassportSession(JWTClaimsSet jwtClaimsSet) throws ParseException {
        PassportSessionItem passportSessionItem = new PassportSessionItem();
        passportSessionItem.setPassportSessionId(SecureTokenHelper.generate());

        LogHelper.attachPassportSessionIdToLogs(passportSessionItem.getPassportSessionId());

        passportSessionItem.setCreationDateTime(Instant.now().toString());
        passportSessionItem.setAttemptCount(0);
        passportSessionItem.setUserId(jwtClaimsSet.getSubject());

        AuthParams authParams =
                new AuthParams(
                        jwtClaimsSet.getStringClaim(RESPONSE_TYPE),
                        jwtClaimsSet.getStringClaim(CLIENT_ID),
                        jwtClaimsSet.getStringClaim(STATE),
                        jwtClaimsSet.getStringClaim(REDIRECT_URI));

        passportSessionItem.setAuthParams(authParams);

        dataStore.create(passportSessionItem);

        return passportSessionItem.getPassportSessionId();
    }

    public void setLatestDcsResponseResourceId(String passportSessionID, String resourceId) {
        PassportSessionItem passportSessionItem = dataStore.getItem(passportSessionID);
        passportSessionItem.setLatestDcsResponseResourceId(resourceId);
        dataStore.update(passportSessionItem);
    }

    public void incrementAttemptCount(String passportSessionID) {
        PassportSessionItem passportSessionItem = dataStore.getItem(passportSessionID);
        passportSessionItem.setAttemptCount(passportSessionItem.getAttemptCount() + 1);
        dataStore.update(passportSessionItem);
    }
}
