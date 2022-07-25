package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.helpers.HttpClientSetUp;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.DCS_POST_URL_PARAM;

public class PassportService {

    public static final String CONTENT_TYPE = "content-type";
    public static final String APPLICATION_JOSE = "application/jose";
    private static final Logger LOGGER = LoggerFactory.getLogger(PassportService.class);
    private final ConfigurationService configurationService;
    private final DataStore<PassportCheckDao> dataStore;
    private final HttpClient httpClient;

    public PassportService(
            HttpClient httpClient,
            ConfigurationService configurationService,
            DataStore<PassportCheckDao> dataStore) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public PassportService(ConfigurationService configurationService)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                EnvironmentVariable.DCS_RESPONSE_TABLE_NAME),
                        PassportCheckDao.class,
                        DataStore.getClient(
                                this.configurationService.getDynamoDbEndpointOverride()),
                        configurationService);
        this.httpClient = HttpClientSetUp.generateHttpClient(this.configurationService);
    }

    public DcsSignedEncryptedResponse dcsPassportCheck(JWSObject payload)
            throws IOException, EmptyDcsResponseException {
        HttpPost request =
                new HttpPost(configurationService.getEnvironmentVariable(DCS_POST_URL_PARAM));
        request.addHeader(CONTENT_TYPE, APPLICATION_JOSE);
        request.setEntity(new StringEntity(payload.serialize()));

        HttpResponse response = httpClient.execute(request);

        if (response == null) {
            throw new EmptyDcsResponseException("Response from DCS is empty");
        }

        if (response.getStatusLine().getStatusCode() != 200) {
            int statusCode = response.getStatusLine().getStatusCode();
            LOGGER.error("Response from DCS has status code: {}", statusCode);
            throw new HttpResponseException(
                    response.getStatusLine().getStatusCode(), "DCS responded with an error");
        }

        return new DcsSignedEncryptedResponse(EntityUtils.toString(response.getEntity()));
    }

    public void persistDcsResponse(PassportCheckDao responsePayload) {
        dataStore.create(responsePayload);
    }
}
