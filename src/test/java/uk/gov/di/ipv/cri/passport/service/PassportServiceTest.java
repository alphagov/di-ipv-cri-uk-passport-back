package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PassportServiceTest {
    public static final String EXPECTED_RESPONSE = "Expected Response";
    public static final String CHECK_PASSPORT_URI = "https://localhost/check/passport";

    @Mock ConfigurationService configurationService;
    @Mock DataStore<DcsResponseItem> dataStore;
    @Mock HttpClient httpClient;
    @Mock JWSObject jwsObject;
    @Mock HttpResponse httpResponse;

    @Captor ArgumentCaptor<HttpPost> httpPost;

    private PassportService underTest;

    @BeforeEach
    void setUp() {
        underTest =
                new PassportService(
                        httpClient,
                        configurationService,
                        dataStore);
    }

    @Test
    void shouldPostToDcsEndpoint() throws IOException {
        String expectedPayload = "Test";
        when(configurationService.getDCSPostUrl()).thenReturn(CHECK_PASSPORT_URI);
        when(httpResponse.toString()).thenReturn(EXPECTED_RESPONSE);
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        when(jwsObject.serialize()).thenReturn(expectedPayload);

        DcsSignedEncryptedResponse actualResponse = underTest.dcsPassportCheck(jwsObject);

        verify(httpClient, times(1)).execute(httpPost.capture());

        assertEquals(CHECK_PASSPORT_URI, httpPost.getValue().getURI().toString());
        assertEquals(
                "application/jose", httpPost.getValue().getFirstHeader("content-type").getValue());
        assertEquals(expectedPayload, EntityUtils.toString(httpPost.getValue().getEntity()));

        assertEquals(EXPECTED_RESPONSE, actualResponse.getPayload());
    }

    @Test
    void shouldReturnNullWhenResponseFromDcsIsNull() throws IOException {
        when(configurationService.getDCSPostUrl()).thenReturn(CHECK_PASSPORT_URI);
        when(httpClient.execute(any(HttpPost.class))).thenReturn(null);
        when(jwsObject.serialize()).thenReturn("Test");
        assertNull(underTest.dcsPassportCheck(jwsObject));
    }

    @Test
    void shouldCreateDcsResponseInDataStore() {
        DcsResponseItem dcsResponse = new DcsResponseItem("UUID", "TEST_PAYLOAD");
        underTest.persistDcsResponse(dcsResponse);
        verify(dataStore).create(dcsResponse);
    }
}
