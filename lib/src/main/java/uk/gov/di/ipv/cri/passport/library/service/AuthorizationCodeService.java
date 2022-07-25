package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.commons.codec.digest.DigestUtils;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AuthorizationCodeItem;

import java.time.Instant;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.AUTH_CODE_EXPIRY_CODE_SECONDS;
import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.CRI_PASSPORT_AUTH_CODES_TABLE_NAME;

public class AuthorizationCodeService {
    private final DataStore<AuthorizationCodeItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationCodeService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        configurationService.getEnvironmentVariable(
                                CRI_PASSPORT_AUTH_CODES_TABLE_NAME),
                        AuthorizationCodeItem.class,
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()),
                        configurationService);
    }

    public AuthorizationCodeService(
            DataStore<AuthorizationCodeItem> dataStore, ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public AuthorizationCode generateAuthorizationCode() {
        return new AuthorizationCode();
    }

    public AuthorizationCodeItem getAuthCodeItem(String authorizationCode) {
        return dataStore.getItem(DigestUtils.sha256Hex(authorizationCode));
    }

    public void persistAuthorizationCode(
            String authorizationCode,
            String resourceId,
            String redirectUrl,
            String passportSessionId) {
        dataStore.create(
                new AuthorizationCodeItem(
                        DigestUtils.sha256Hex(authorizationCode),
                        resourceId,
                        redirectUrl,
                        Instant.now().toString(),
                        passportSessionId));
    }

    public void persistAuthorizationCode(String authorizationCode, String passportSessionId) {
        dataStore.create(
                new AuthorizationCodeItem(
                        DigestUtils.sha256Hex(authorizationCode),
                        Instant.now().toString(),
                        passportSessionId));
    }

    public void setIssuedAccessToken(String authorizationCode, String accessToken) {
        AuthorizationCodeItem authorizationCodeItem = dataStore.getItem(authorizationCode);
        authorizationCodeItem.setIssuedAccessToken(DigestUtils.sha256Hex(accessToken));
        authorizationCodeItem.setExchangeDateTime(Instant.now().toString());

        dataStore.update(authorizationCodeItem);
    }

    public boolean isExpired(AuthorizationCodeItem authCodeItem) {
        return Instant.parse(authCodeItem.getCreationDateTime())
                .isBefore(
                        Instant.now()
                                .minusSeconds(
                                        Long.parseLong(
                                                configurationService.getSsmParameter(
                                                        AUTH_CODE_EXPIRY_CODE_SECONDS))));
    }
}
