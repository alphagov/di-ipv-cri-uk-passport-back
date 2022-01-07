package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.cri.passport.validation.ValidationResult;

import java.net.URI;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class AccessTokenServiceTest {
    private DataStore<AccessTokenItem> mockDataStore;
    private ConfigurationService mockConfigurationService;
    private AccessTokenService accessTokenService;

    @BeforeEach
    void setUp() {
        this.mockConfigurationService = mock(ConfigurationService.class);
        this.mockDataStore = mock(DataStore.class);
        this.accessTokenService = new AccessTokenService(mockDataStore, mockConfigurationService);
    }

    @Test
    void shouldReturnSuccessfulTokenResponseOnSuccessfulExchange() throws Exception {
        long testTokenTtl = 2400L;
        Scope testScope = new Scope("test-scope");
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new AuthorizationCodeGrant(
                                new AuthorizationCode("123456"), new URI("http://test.com")),
                        testScope);
        when(mockConfigurationService.getBearerAccessTokenTtl()).thenReturn(testTokenTtl);

        TokenResponse response = accessTokenService.generateAccessToken(tokenRequest);

        assertInstanceOf(AccessTokenResponse.class, response);
        assertNotNull(response.toSuccessResponse().getTokens().getAccessToken().getValue());
        assertEquals(
                testTokenTtl,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getLifetime());
        assertEquals(
                testScope,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getScope());
    }

    @Test
    void shouldReturnValidationErrorWhenInvalidGrantTypeProvided() {
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new RefreshTokenGrant(new RefreshToken()));

        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateTokenRequest(tokenRequest);

        assertNotNull(validationResult);
        assertFalse(validationResult.isValid());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, validationResult.getError());
    }

    @Test
    void shouldNotReturnValidationErrorWhenAValidTokenRequestIsProvided() {
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new AuthorizationCodeGrant(
                                new AuthorizationCode(), URI.create("https://test.com")));

        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateTokenRequest(tokenRequest);

        assertNotNull(validationResult);
        assertTrue(validationResult.isValid());
        assertNull(validationResult.getError());
    }

    @Test
    void shouldPersistAccessToken() {
        String testResourceId = UUID.randomUUID().toString();
        AccessToken accessToken = new BearerAccessToken();
        AccessTokenResponse accessTokenResponse =
                new AccessTokenResponse(new Tokens(accessToken, null));
        ArgumentCaptor<AccessTokenItem> accessTokenItemArgCaptor =
                ArgumentCaptor.forClass(AccessTokenItem.class);

        accessTokenService.persistAccessToken(accessTokenResponse, testResourceId);

        verify(mockDataStore).create(accessTokenItemArgCaptor.capture());
        AccessTokenItem capturedAccessTokenItem = accessTokenItemArgCaptor.getValue();
        assertNotNull(capturedAccessTokenItem);
        assertEquals(testResourceId, capturedAccessTokenItem.getResourceId());
        assertEquals(
                accessTokenResponse.getTokens().getBearerAccessToken().toAuthorizationHeader(),
                capturedAccessTokenItem.getAccessToken());
    }

    @Test
    void shouldGetSessionIdByAccessTokenWhenValidAccessTokenProvided() {
        String testResourceId = UUID.randomUUID().toString();
        String accessToken = new BearerAccessToken().toAuthorizationHeader();

        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setResourceId(testResourceId);
        when(mockDataStore.getItem(accessToken)).thenReturn(accessTokenItem);

        String resultIpvSessionId = accessTokenService.getResourceIdByAccessToken(accessToken);

        verify(mockDataStore).getItem(accessToken);

        assertNotNull(resultIpvSessionId);
        assertEquals(testResourceId, resultIpvSessionId);
    }

    @Test
    void shouldReturnNullWhenInvalidAccessTokenProvided() {
        String accessToken = new BearerAccessToken().toAuthorizationHeader();

        when(mockDataStore.getItem(accessToken)).thenReturn(null);

        String resultIpvSessionId = accessTokenService.getResourceIdByAccessToken(accessToken);

        verify(mockDataStore).getItem(accessToken);
        assertNull(resultIpvSessionId);
    }
}