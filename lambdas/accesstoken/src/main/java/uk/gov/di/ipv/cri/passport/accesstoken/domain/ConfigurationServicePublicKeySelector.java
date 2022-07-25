package uk.gov.di.ipv.cri.passport.accesstoken.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.List;

public class ConfigurationServicePublicKeySelector implements ClientCredentialsSelector<Object> {

    private final ConfigurationService configurationService;

    public ConfigurationServicePublicKeySelector(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public List<Secret> selectClientSecrets(
            ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) {
        throw new UnsupportedOperationException("We don't do that round here...");
    }

    @Override
    public List<? extends PublicKey> selectPublicKeys(
            ClientID claimedClientID,
            ClientAuthenticationMethod authMethod,
            JWSHeader jwsHeader,
            boolean forceRefresh,
            Context context)
            throws InvalidClientException {
        try {
            return List.of(
                    configurationService
                            .getClientSigningPublicJwk(claimedClientID.getValue())
                            .toECPublicKey());
        } catch (ParseException | JOSEException e) {
            throw new InvalidClientException(e.getMessage());
        }
    }
}
