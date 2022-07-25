package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AuthorizationCodeItem;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.AUTH_CODE_EXPIRY_CODE_SECONDS;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeServiceTest {

    @Mock private DataStore<AuthorizationCodeItem> mockDataStore;
    @Mock private ConfigurationService configurationService;
    @InjectMocks AuthorizationCodeService authorizationCodeService;

    @Test
    void shouldReturnAnAuthorisationCode() {
        AuthorizationCode result = authorizationCodeService.generateAuthorizationCode();

        assertNotNull(result);
    }

    @Test
    void shouldCreateAuthorizationCodeInDataStore() {
        AuthorizationCode testCode = new AuthorizationCode();
        String resourceId = "resource-12345";
        String redirectUrl = "http://example.com";
        String testPassportSessionId = "testPassportSessionId";
        authorizationCodeService.persistAuthorizationCode(
                testCode.getValue(), resourceId, redirectUrl, testPassportSessionId);

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(AuthorizationCodeItem.class);
        verify(mockDataStore).create(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(resourceId, authorizationCodeItemArgumentCaptor.getValue().getResourceId());
        assertEquals(
                testPassportSessionId,
                authorizationCodeItemArgumentCaptor.getValue().getPassportSessionId());
        assertEquals(
                DigestUtils.sha256Hex(testCode.getValue()),
                authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(redirectUrl, authorizationCodeItemArgumentCaptor.getValue().getRedirectUrl());
    }

    @Test
    void shouldGetResourceIdByAuthCodeWhenValidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();
        String resourceId = "resource-12345";

        AuthorizationCodeItem testItem = new AuthorizationCodeItem();
        testItem.setResourceId(resourceId);
        testItem.setAuthCode(new AuthorizationCode().getValue());
        testItem.setRedirectUrl("http://example.com");
        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue())))
                .thenReturn(testItem);

        AuthorizationCodeItem resultAuthCodeItem =
                authorizationCodeService.getAuthCodeItem(testCode.getValue());

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertEquals(resourceId, resultAuthCodeItem.getResourceId());
        assertEquals(testItem.getAuthCode(), resultAuthCodeItem.getAuthCode());
        assertEquals(testItem.getRedirectUrl(), resultAuthCodeItem.getRedirectUrl());
    }

    @Test
    void shouldReturnNullWhenInvalidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();

        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue()))).thenReturn(null);

        AuthorizationCodeItem resultAuthCodeItem =
                authorizationCodeService.getAuthCodeItem(testCode.getValue());

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertNull(resultAuthCodeItem);
    }

    @Test
    void shouldCallUpdateWithIssuedAccessTokenValue() {
        AuthorizationCode testCode = new AuthorizationCode();
        AuthorizationCodeItem authorizationCodeItem =
                new AuthorizationCodeItem(
                        testCode.getValue(),
                        "test-resource",
                        "http://example.com",
                        Instant.now().toString(),
                        UUID.randomUUID().toString());

        when(mockDataStore.getItem(testCode.getValue())).thenReturn(authorizationCodeItem);
        authorizationCodeService.setIssuedAccessToken(testCode.getValue(), "test-access-token");

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(AuthorizationCodeItem.class);
        verify(mockDataStore).update(authorizationCodeItemArgumentCaptor.capture());

        assertNotNull(authorizationCodeItemArgumentCaptor.getValue().getExchangeDateTime());
    }

    @Test
    void isExpiredReturnsTrueIfAuthCodeItemHasExpired() {
        when(configurationService.getSsmParameter(AUTH_CODE_EXPIRY_CODE_SECONDS)).thenReturn("600");
        AuthorizationCodeItem expiredAuthCodeItem =
                new AuthorizationCodeItem(
                        "auth-code",
                        "resource-id",
                        "redirect-url",
                        Instant.now().minusSeconds(601).toString(),
                        "passport-session-id");

        assertTrue(authorizationCodeService.isExpired(expiredAuthCodeItem));
    }

    @Test
    void isExpiredReturnsFalseIfAuthCodeItemHasNotExpired() {
        when(configurationService.getSsmParameter(AUTH_CODE_EXPIRY_CODE_SECONDS)).thenReturn("600");
        AuthorizationCodeItem expiredAuthCodeItem =
                new AuthorizationCodeItem(
                        "auth-code",
                        "resource-id",
                        "redirect-url",
                        Instant.now().minusSeconds(599).toString(),
                        "passport-session-id");

        assertFalse(authorizationCodeService.isExpired(expiredAuthCodeItem));
    }
}
