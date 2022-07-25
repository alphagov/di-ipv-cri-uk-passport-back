package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;

import java.text.ParseException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PassportSessionServiceTest {
    @Mock ConfigurationService configurationService;
    @Mock DataStore<PassportSessionItem> mockDataStore;

    private PassportSessionService underTest;

    @BeforeEach
    void setUp() {
        underTest = new PassportSessionService(mockDataStore, configurationService);
    }

    @Test
    void shouldReturnSessionItem() {
        String passportSessionID = SecureTokenHelper.generate();

        PassportSessionItem passportSessionItem = new PassportSessionItem();
        passportSessionItem.setPassportSessionId(passportSessionID);
        passportSessionItem.setCreationDateTime(new Date().toString());

        when(mockDataStore.getItem(passportSessionID)).thenReturn(passportSessionItem);

        PassportSessionItem result = underTest.getPassportSession(passportSessionID);

        ArgumentCaptor<String> passportSessionIDArgumentCaptor =
                ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).getItem(passportSessionIDArgumentCaptor.capture());
        assertEquals(passportSessionID, passportSessionIDArgumentCaptor.getValue());
        assertEquals(passportSessionItem.getPassportSessionId(), result.getPassportSessionId());
        assertEquals(passportSessionItem.getCreationDateTime(), result.getCreationDateTime());
    }

    @Test
    void shouldCreateSessionItem() throws ParseException {
        JWTClaimsSet jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("redirect_url", "http://example.com")
                        .claim("client_id", "ipv-core")
                        .build();

        String passportSessionID = underTest.generatePassportSession(jwtClaimsSet);

        ArgumentCaptor<PassportSessionItem> passportSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(PassportSessionItem.class);
        verify(mockDataStore).create(passportSessionItemArgumentCaptor.capture());
        assertNotNull(passportSessionItemArgumentCaptor.getValue().getCreationDateTime());
        assertEquals(
                passportSessionItemArgumentCaptor.getValue().getPassportSessionId(),
                passportSessionID);
    }

    @Test
    void shouldUpdateLatestDcsResponseResourceId() {
        String passportSessionID = SecureTokenHelper.generate();
        String latestDcsResponseResourceId = "test";

        when(mockDataStore.getItem(passportSessionID)).thenReturn(new PassportSessionItem());
        underTest.setLatestDcsResponseResourceId(passportSessionID, latestDcsResponseResourceId);

        ArgumentCaptor<PassportSessionItem> passportSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(PassportSessionItem.class);
        verify(mockDataStore).update(passportSessionItemArgumentCaptor.capture());
        assertEquals(
                passportSessionItemArgumentCaptor.getValue().getLatestDcsResponseResourceId(),
                latestDcsResponseResourceId);
    }

    @Test
    void shouldIncrementAttemptCount() {
        String passportSessionID = SecureTokenHelper.generate();

        PassportSessionItem passportSessionItem = new PassportSessionItem();
        passportSessionItem.setAttemptCount(1);

        when(mockDataStore.getItem(passportSessionID)).thenReturn(passportSessionItem);
        underTest.incrementAttemptCount(passportSessionID);

        ArgumentCaptor<PassportSessionItem> passportSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(PassportSessionItem.class);
        verify(mockDataStore).update(passportSessionItemArgumentCaptor.capture());
        assertEquals(2, passportSessionItemArgumentCaptor.getValue().getAttemptCount());
    }
}
