package uk.gov.di.ipv.cri.passport.library.config;

public enum ConfigurationVariable {
    AUTH_CODE_EXPIRY_CODE_SECONDS("/%s/credentialIssuers/ukPassport/self/authCodeExpirySeconds"),
    BACKEND_SESSION_TTL("/%s/credentialIssuers/ukPassport/self/backendSessionTtl"),

    DCS_ENCRYPTION_CERT("/%s/credentialIssuers/ukPassport/dcs/encryptionCertForPassportToEncrypt"),
    DCS_SIGNING_CERT("/%s/credentialIssuers/ukPassport/dcs/signingCertForPassportToVerify"),
    DCS_TLS_INTERMEDIATE_CERT("/%s/credentialIssuers/ukPassport/dcs/tlsIntermediateCertificate"),
    DCS_TLS_ROOT_CERT("/%s/credentialIssuers/ukPassport/dcs/tlsRootCertificate"),
    JAR_ENCRYPTION_KEY_ID("/%s/credentialIssuers/ukPassport/self/jarKmsEncryptionKeyId"),
    JAR_KMS_PUBLIC_KEY("/%s/credentialIssuers/ukPassport/self/jarKmsEncryptionPublicKey"),
    MAX_JWT_TTL("/%s/credentialIssuers/ukPassport/self/maxJwtTtl"),
    MAXIMUM_ATTEMPT_COUNT("/%s/credentialIssuers/ukPassport/self/maximumAttemptCount"),
    PASSPORT_CRI_CLIENT_AUDIENCE("/%s/credentialIssuers/ukPassport/self/audienceForClients"),
    PASSPORT_CRI_CLIENT_AUTH_MAX_TTL("/%s/credentialIssuers/ukPassport/self/maxJwtTtl"),

    PASSPORT_CRI_ENCRYPTION_KEY(
            "/%s/credentialIssuers/ukPassport/self/encryptionKeyForPassportToDecrypt"),
    PASSPORT_CRI_SIGNING_CERT("/%s/credentialIssuers/ukPassport/self/signingCertForDcsToVerify"),
    PASSPORT_CRI_SIGNING_KEY("/%s/credentialIssuers/ukPassport/self/signingKeyForPassportToSign"),
    PASSPORT_CRI_TLS_CERT("/%s/credentialIssuers/ukPassport/self/tlsCert"),
    PASSPORT_CRI_TLS_KEY("/%s/credentialIssuers/ukPassport/self/tlsKey"),
    VERIFIABLE_CREDENTIAL_ISSUER(
            "/%s/credentialIssuers/ukPassport/self/verifiableCredentialIssuer"),
    VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID(
            "/%s/credentialIssuers/ukPassport/self/verifiableCredentialKmsSigningKeyId");

    private final String value;

    ConfigurationVariable(String value) {

        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
