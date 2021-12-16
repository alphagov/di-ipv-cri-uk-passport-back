package uk.gov.di.ipv.cri.passport.kms;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Set;

public class KmsSigner implements JWSSigner {

    private static final Base64.Encoder b64UrlEncoder = Base64.getUrlEncoder();
    private final AWSKMS kmsClient;
    private final JCAContext jcaContext = new JCAContext();
    private final String keyId;

    public KmsSigner(String keyId, AWSKMS kmsClient) {
        this.keyId = keyId;
        this.kmsClient = kmsClient;
    }

    public KmsSigner(String keyId) {
        this.keyId = keyId;
        kmsClient = AWSKMSClientBuilder.defaultClient();
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) {

        SignRequest signRequest =
            new SignRequest()
                .withSigningAlgorithm(
                    SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.toString())
                .withKeyId(keyId)
                .withMessage(ByteBuffer.wrap(signingInput))
                .withMessageType(MessageType.RAW);

        SignResult signResult = kmsClient.sign(signRequest);

        return new Base64URL(b64UrlEncoder.encodeToString(signResult.getSignature().array()));
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(RS256);
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }
}