package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.time.Instant;
import java.util.Objects;

import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.CRI_PASSPORT_ACCESS_TOKENS_TABLE_NAME;

public class AccessTokenService {
    protected static final Scope DEFAULT_SCOPE = new Scope("user-credentials");
    private final DataStore<AccessTokenItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                CRI_PASSPORT_ACCESS_TOKENS_TABLE_NAME),
                        AccessTokenItem.class,
                        DataStore.getClient(
                                this.configurationService.getDynamoDbEndpointOverride()),
                        this.configurationService);
    }

    public AccessTokenService(
            DataStore<AccessTokenItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public TokenResponse generateAccessToken() {
        AccessToken accessToken =
                new BearerAccessToken(
                        configurationService.getAccessTokenExpirySeconds(), DEFAULT_SCOPE);
        return new AccessTokenResponse(new Tokens(accessToken, null));
    }

    public ValidationResult<ErrorObject> validateAuthorizationGrant(AuthorizationGrant authGrant) {
        if (!authGrant.getType().equals(GrantType.AUTHORIZATION_CODE)) {
            return new ValidationResult<>(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }
        return ValidationResult.createValidResult();
    }

    public AccessTokenItem getAccessTokenItem(String accessToken) {
        AccessTokenItem accessTokenItem = dataStore.getItem(DigestUtils.sha256Hex(accessToken));
        if (accessTokenItem != null) {
            LogHelper.attachPassportSessionIdToLogs(accessTokenItem.getPassportSessionId());
        }
        return accessTokenItem;
    }

    public void persistAccessToken(
            AccessTokenResponse tokenResponse, String resourceId, String passportSessionId) {
        BearerAccessToken accessToken = tokenResponse.getTokens().getBearerAccessToken();
        dataStore.create(
                new AccessTokenItem(
                        DigestUtils.sha256Hex(accessToken.getValue()),
                        resourceId,
                        toExpiryDateTime(accessToken.getLifetime()),
                        passportSessionId));
    }

    public void revokeAccessToken(String accessToken) throws IllegalArgumentException {
        AccessTokenItem accessTokenItem = dataStore.getItem(accessToken);

        if (Objects.nonNull(accessTokenItem)) {
            if (StringUtils.isBlank(accessTokenItem.getRevokedAtDateTime())) {
                accessTokenItem.setRevokedAtDateTime(Instant.now().toString());
                dataStore.update(accessTokenItem);
            }
        } else {
            throw new IllegalArgumentException(
                    "Failed to revoke access token - access token could not be found in DynamoDB");
        }
    }

    private String toExpiryDateTime(long expirySeconds) {
        return Instant.now().plusSeconds(expirySeconds).toString();
    }
}
