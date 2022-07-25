package uk.gov.di.ipv.cri.passport.integrationtest;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.KmsRsaDecrypter;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.JAR_ENCRYPTION_KEY_ID;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.JAR_KMS_PUBLIC_KEY;

class KmsRsaDecrypterIT {
    private static ConfigurationService configurationService;

    @BeforeAll
    public static void setup() {
        configurationService = new ConfigurationService();
    }

    @Test
    void decryptWithKms() throws Exception {
        String getJarKmsEncryptionKeyId = System.getenv("JAR_ENCRYPTION_KEY_ID_PARAM");
        if (getJarKmsEncryptionKeyId == null) {
            throw new IllegalArgumentException(
                    "The environment variable 'JAR_ENCRYPTION_KEY_ID_PARAM' must be provided to run this test");
        }

        String getJarKmsPublickKey = System.getenv("JAR_KMS_PUBLIC_KEY_PARAM");
        if (getJarKmsPublickKey == null) {
            throw new IllegalArgumentException(
                    "The environment variable 'JAR_KMS_PUBLIC_KEY_PARAM' must be provided to run this test");
        }

        String kmsId = configurationService.getSsmParameter(JAR_ENCRYPTION_KEY_ID);
        String pubKey = configurationService.getSsmParameter(JAR_KMS_PUBLIC_KEY);

        var header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        JWEObject jweObject = new JWEObject(header, new Payload("Decrypt me!"));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey =
                (RSAPublicKey)
                        keyFactory.generatePublic(
                                new X509EncodedKeySpec(Base64.getDecoder().decode(pubKey)));
        jweObject.encrypt(new RSAEncrypter(publicKey));

        jweObject.decrypt(new KmsRsaDecrypter(kmsId));
        String s = jweObject.getPayload().toString();

        assertEquals("Decrypt me!", s);
    }
}
