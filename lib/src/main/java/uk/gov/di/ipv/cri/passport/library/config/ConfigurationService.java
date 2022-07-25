package uk.gov.di.ipv.cri.passport.library.config;

import com.nimbusds.jose.jwk.ECKey;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.library.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.library.exceptions.UnknownClientException;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.PASSPORT_CRI_SIGNING_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.BEARER_TOKEN_TTL;
import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.DYNAMODB_ENDPOINT_OVERRIDE;
import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.ENVIRONMENT;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS = 3600L;
    private static final String IS_LOCAL = "IS_LOCAL";
    private static final String CLIENT_REDIRECT_URL_SEPARATOR = ",";
    public static final String CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX =
            "CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX";

    private final SSMProvider ssmProvider;

    public ConfigurationService(SSMProvider ssmProvider) {
        this.ssmProvider = ssmProvider;
    }

    public ConfigurationService() {
        if (isRunningLocally()) {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .endpointOverride(URI.create(LOCALHOST_URI))
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .region(Region.EU_WEST_2)
                                    .build());
        } else {
            this.ssmProvider = ParamManager.getSsmProvider();
        }
    }

    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv(IS_LOCAL));
    }

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    public String getSsmParameter(ConfigurationVariable configurationVariable) {
        return ssmProvider.get(
                String.format(
                        configurationVariable.getValue(), getEnvironmentVariable(ENVIRONMENT)));
    }

    public String getEncryptedSsmParameter(ConfigurationVariable configurationVariable) {
        return ssmProvider
                .withDecryption()
                .get(
                        String.format(
                                configurationVariable.getValue(),
                                getEnvironmentVariable(ENVIRONMENT)));
    }

    public Certificate getCertificate(ConfigurationVariable configurationVariable)
            throws CertificateException {
        byte[] binaryCertificate =
                Base64.getDecoder().decode(getEncryptedSsmParameter(configurationVariable));
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

    public PrivateKey getPrivateKey(ConfigurationVariable configurationVariable)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] binaryKey =
                Base64.getDecoder().decode(getEncryptedSsmParameter(configurationVariable));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(binaryKey);
        return factory.generatePrivate(privateKeySpec);
    }

    public Thumbprints makeThumbprints() throws CertificateException, NoSuchAlgorithmException {
        var cert = getCertificate(PASSPORT_CRI_SIGNING_CERT);
        return new Thumbprints(
                getThumbprint((X509Certificate) cert, "SHA-1"),
                getThumbprint((X509Certificate) cert, "SHA-256"));
    }

    public String getThumbprint(X509Certificate cert, String hashAlg)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public long getAccessTokenExpirySeconds() {
        return Optional.ofNullable(getEnvironmentVariable(BEARER_TOKEN_TTL))
                .map(Long::valueOf)
                .orElse(DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS);
    }

    public URI getDynamoDbEndpointOverride() {
        String dynamoDbEndpointOverride = getEnvironmentVariable(DYNAMODB_ENDPOINT_OVERRIDE);
        if (dynamoDbEndpointOverride != null && !dynamoDbEndpointOverride.isEmpty()) {
            return URI.create(dynamoDbEndpointOverride);
        }
        return null;
    }

    public ECKey getClientSigningPublicJwk(String clientId) throws ParseException {
        return ECKey.parse(
                ssmProvider.get(
                        String.format(
                                "%s/%s/signingPublicJwk",
                                System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), clientId)));
    }

    public List<String> getClientRedirectUrls(String clientId) throws UnknownClientException {
        String redirectUrlStrings =
                ssmProvider.get(
                        String.format(
                                "%s/%s/jwtAuthentication/validRedirectUrls",
                                System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), clientId));

        return Arrays.asList(redirectUrlStrings.split(CLIENT_REDIRECT_URL_SEPARATOR));
    }

    public String getClientIssuer(String clientId) throws UnknownClientException {
        return ssmProvider.get(
                String.format(
                        "%s/%s/jwtAuthentication/issuer",
                        System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), clientId));
    }
}
