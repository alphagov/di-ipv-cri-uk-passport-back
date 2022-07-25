package uk.gov.di.ipv.cri.passport.accesstoken.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PUBLIC_JWK_1;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PUBLIC_JWK_2;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PUBLIC_JWK_3;

@ExtendWith(MockitoExtension.class)
class ConfigurationServicePublicKeySelectorTest {

    @Mock ConfigurationService mockConfigurationService;
    @InjectMocks ConfigurationServicePublicKeySelector keySelector;

    @Test
    void selectClientSecretsThrowsUnsupportedOperationException() {
        assertThrows(
                UnsupportedOperationException.class,
                () -> keySelector.selectClientSecrets(null, null, null));
    }

    @Test
    void selectPublicKeysShouldReturnAListOfClientEcPublicKeys() throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk("testClientId1"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));
        when(mockConfigurationService.getClientSigningPublicJwk("testClientId2"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_2));
        when(mockConfigurationService.getClientSigningPublicJwk("testClientId3"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_3));

        List<? extends PublicKey> publicKeys2 =
                keySelector.selectPublicKeys(
                        new ClientID("testClientId2"), null, null, false, null);

        List<? extends PublicKey> publicKeys3 =
                keySelector.selectPublicKeys(
                        new ClientID("testClientId3"), null, null, false, null);

        List<? extends PublicKey> publicKeys1 =
                keySelector.selectPublicKeys(
                        new ClientID("testClientId1"), null, null, false, null);

        assertEquals(ECKey.parse(EC_PUBLIC_JWK_1).toECPublicKey(), publicKeys1.get(0));
        assertEquals(ECKey.parse(EC_PUBLIC_JWK_2).toECPublicKey(), publicKeys2.get(0));
        assertEquals(ECKey.parse(EC_PUBLIC_JWK_3).toECPublicKey(), publicKeys3.get(0));
    }

    @Test
    void selectPublicKeysShouldThrowInvalidClientExceptionIfCanNotParsePublicJwk()
            throws Exception {
        when(mockConfigurationService.getClientSigningPublicJwk("testClientId"))
                .thenThrow(new ParseException("Not a JWK", 0));

        InvalidClientException exception =
                assertThrows(
                        InvalidClientException.class,
                        () ->
                                keySelector.selectPublicKeys(
                                        new ClientID("testClientId"), null, null, false, null));
        assertEquals("Not a JWK", exception.getMessage());
    }

    @Test
    void selectPublicKeysShouldThrowInvalidClientExceptionIfCanNotConvertKeyToJavaInterfaceEcKey()
            throws Exception {
        ECKey ecKeyMock = mock(ECKey.class);
        when(ecKeyMock.toECPublicKey()).thenThrow(new JOSEException("Something went wrong..."));
        when(mockConfigurationService.getClientSigningPublicJwk("testClientId"))
                .thenReturn(ecKeyMock);

        InvalidClientException exception =
                assertThrows(
                        InvalidClientException.class,
                        () ->
                                keySelector.selectPublicKeys(
                                        new ClientID("testClientId"), null, null, false, null));
        assertEquals("Something went wrong...", exception.getMessage());
    }
}
