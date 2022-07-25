package uk.gov.di.ipv.cri.passport.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.library.exceptions.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.library.utils.TestUtils;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.DCS_ENCRYPTION_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.DCS_SIGNING_CERT;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.PASSPORT_CRI_ENCRYPTION_KEY;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.PASSPORT_CRI_SIGNING_KEY;

@ExtendWith(MockitoExtension.class)
class DcsCryptographyServiceTest {
    public static final String BASE64_DCS_SIGNING_CERT =
            "MIIFVjCCAz4CCQDGbJ/u6uFT6DANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQGEwJHQjENMAsGA1UECAwEVGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEVEVzdDENMAsGA1UECwwEVEVzdDENMAsGA1UEAwwEVEVzdDETMBEGCSqGSIb3DQEJARYEVGVzdDAeFw0yMjAxMDcxNTM0NTlaFw0yMzAxMDcxNTM0NTlaMG0xCzAJBgNVBAYTAkdCMQ0wCwYDVQQIDARUZXN0MQ0wCwYDVQQHDARUZXN0MQ0wCwYDVQQKDARURXN0MQ0wCwYDVQQLDARURXN0MQ0wCwYDVQQDDARURXN0MRMwEQYJKoZIhvcNAQkBFgRUZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy1cVZ1KfFmgFlDQyf/R3LF/Js6jAS2Zzbs8WGSS0ys6Z+XR4x5DTIznZp5cHuuQmqOFylXSw5oGBwMXd2L6NimG9rJnJ4w8Gy5A6ImGsiDZC+3AXRBb5hq/IdDTBjbUqRxAKokSVwotWZt554BdSRPTmlYDujzxnClNKA06Xb/X3rTsgCUmZhUnSVtOzKytP3Bdv88VI5gq5tlZOtKXCB0PnJOqRbBmuL1RNkeTny4ZJW3I2ywSATwDDyDm4pJ8XGGNFKaYYTwr6uNTQ2VHb1FVC33oWbg+Zu9D4p5l7ONicCCF3V+GbvmyeCmHGnXznz0nYX1LFqaKtruEh3/GXyLy5X03Jzq6HhTf1SNFBmzziuCovhbR4v5aFDqAYNPWz+ajOdTUfP1I18c5jR1xGUxEiiLKBZWU1J5mhqCa+0CdI0mi3HwFmluudh47I2Xw++JiqZQpxRqNGcKJOPnWDgKOKXQ/ag37aJkxqoYWk9pQ/pXOdIKm//+B//8nWGo8BA/bfdmMHyzhWWxqtydjie2EZ5ODSdQ+yu1xU5cwP59BEQoU7FKVEGiJa4kzrsI2cgloUPlsPfLENMa5i09exDo//eDB/zNy9ACgGCriov1ex3uv4vHp3WtpZYe+akGEJeP0N5dejs0hkBuX+LUcM30TnQ424tEzcuaJ1F7r4FP0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAUh5gZx8S/XoZZoQai2uTyW/lyr1LpXMQyfvdWRr5+/OtFuASG3fAPXOTiUfuqH6Uma8BaXPRbSGWxBOFg0EbyvUY4UczZXZgVqyzkGjD2bVcnGra1OHz2AkcJm7OvzjMUvmXdDiQ8WcKIH16BZVsJFveTffJbM/KxL9UUdSLT0fNw1OvZWN1LxRj+X16B26ZnmaXPdmEC8MfwNcEU63qSlIbAvLg9Dp03weqO1qWR1vI/n1jwqidCUVwT0XF88/pJrds8/8guKlawhp9Yv+jMVYaawBiALR+5PFN56DivtmSVI5uv3oFh5tqJXXn9PhsPcIq0YKGQvvcdZl7vCikS65VzmswXBVFJNsYeeZ5NmiH2ANQd4+BLetgLAoXZxaOJ4nK+3Ml+gMwpZRRAbtixKJQDtVy+Ahuh1TEwTS1CERDYq43LhVYbMcgxdOLpZLvMew2tvJc3HfSWQKuF+NjGn/RwG54GyhjpdbfNZMB/EJXNJMt1j9RSVbPLsWjaENUkZoXE0otSou9tJOR0fwoqBJGUi5GCp98+iBdIQMAvXW5JkoDS6CM1FOfSv9ZXLvfXHOuBfKTDeVNy7u3QvyJ+BdkSc0iH4gj1F2zLHNIaZbDzwRzcDf2s3D1wTtoJ/WxfRSLGBMuUsXSduh9Md1S862N3Ce6wpri1IsgySCP84Y=";
    public static final String BASE64_DCS_SIGNING_KEY =
            "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";
    public static final String BASE64_SIGNING_PRIVATE_KEY =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMUiC17ZaXozJZBH5N2Vsqdy+b8Vq1q043cZi9BxL4BAL9gkdqFI9HCiOxskqKQXE96jt/u6h4d1EECfrpM/pwVBXVnM8iKukUP62+SsrPdG+jgP+QVB6xTJkYuKV9nd1akgdVjiHQOnx3v03+OInhdhmTP7ob9nvUuLHFtM6xRKRFooGrELRnOpJRV4GsAWXjCHPyOzHNv2Ipk08v9VZfEIlCjHnHPC+pVSF5E4p2dOp0OKsKRQBFG5al9f4BP5y1Qw2z1mJgJV1w5QElGNgNACFKAR959b7rk1JxqPVaFwWe7T/XL+xFD0VrZNEUrozNl48sRXtiwxJU/yDj3J91AgMBAAECggEBALgss8WqQ5uuhNzO+xcrfU0bIHQ+LBkkMJ4zrI1/ye58l0Fy5PLPU5OipSgxYZWchfpcoIN0YdktHH86i80YiIAmm4PxFJlk+rLA79lfS8+S0msdBcFQwlXpiPtKvgosefKBPVE2jG5JuharAB/PUSJFtaoQwK8iEN9gGQbxA3uvmeWWQvxjPuC0/C/Bm2Tm+x5UrvfflqNRXXL3X/QkhU1ZHH/577w3Meua/wPcWVc7kUWhD3pMZDGM//uyYRQezC5oDKMtYAyN/YyiuF4oB3h8wiNtI54/px/caIJWzVk+zg1hqVTByG/MRWYqKIFVhzd58HfUi4vSB/1WR+PLoqECgYEA9PwZGTqqC2Mn9A3gHW882Go+rN/Owc+cOk4Z/C4ho9uh5v2EqaKPMDZkAY1E+FFThQej8ojrVIxoUK9gSQgpa+qOobDsgGrWVSqiP8u0L4M+Xn3Fg5MGquJ0voZ8t6CbdC+u7CV/RgtUnspGm3JgsARO8pOT4LCmwxzbdmDG+ikCgYEA1YH3cOmbd39cVMGE9YGYQF1ujEttkzCKOnfZHbUeOPSnx7FypKOMFaMig9NebsSzzyE2MtIDnm04D8ddnYtIA/y1Lho11rweo9SZ6hfSWU+xENABj9lY54hvQtuWmm9Hqi/BRdRaXncJOX9iQm252I1st+yiE2hM43YmcV2+vG0CgYAWfvfHC04GEarfjE6iJU7PCKKMuViBD5FnATj9oTbRlx982JbQBO9lG/l+8vv8WWtz8cmqQcxqTSJfFlufGTLEiBtk2Zw+BpF77JhNh2UaX9DgWGhEtsGL+5OA01SsgAEGYEKNyLuxMOUqV6S4LX6Xay3ctJSFs3L8w6+bZTOgUQKBgDWlgVnyqKie7MEzGshhNrM9hrBjp3WrZaAJSxmGz8A54QpxEMBDg8hQBDUhYAHvFMr/qlGcqWIeSU7VpjUWsRKnZZLe7RY2kHBT1BSYxbbBKllyGmJdl1Qd2O7wo+fL/DLL6wEzuT0xJbU3x6WvUloSNvYD1DmSJHem0UP87RcFAoGAS3Ucq788OvYge2a06J+SShSBWgG6cuMUwU+NUmsfAqjWQTDSdG63Atrb6jXC/r2gtZuuZSIXukRfKY1pLTrNpOaNfb/S8RWXIR/x6x88GZoMn00u9S+j+c3vzlRfJO2aOiOuClxDta+npCSK4NNna5BuJa/Cr7UewRm4U8D8oWM=";
    public static final String BASE64_ENCRYPTION_PUBLIC_CERT =
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZEakNDQXZZQ0NRQ3JjK3ppU2ZNeUR6QU5CZ2txaGtpRzl3MEJBUXNGQURCSk1Rc3dDUVlEVlFRR0V3SkgKUWpFTk1Bc0dBMVVFQ0F3RVZHVnpkREVOTUFzR0ExVUVCd3dFVkdWemRERU5NQXNHQTFVRUNnd0VWRVZ6ZERFTgpNQXNHQTFVRUN3d0VWR1Z6ZERBZUZ3MHlNVEV5TWpNeE1EVTJNakZhRncweU1qRXlNak14TURVMk1qRmFNRWt4CkN6QUpCZ05WQkFZVEFrZENNUTB3Q3dZRFZRUUlEQVJVWlhOME1RMHdDd1lEVlFRSERBUlVaWE4wTVEwd0N3WUQKVlFRS0RBUlVSWE4wTVEwd0N3WURWUVFMREFSVVpYTjBNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QQpNSUlDQ2dLQ0FnRUF3RnJkUzhFUUNLaUQxNXJ1UkE3SFd5T0doeVZ0TlphV3JYOUVGZWNJZTZPQWJCRHhHS2NQCkJLbVJVMDNud3g1THppRWhNL2NlNWw0a3lTazcybFgwYSt6ZTVkb2pqZkx6dFJZcGdiSTlEYUVwMy9GTEdyWkoKRmpPZCtwaU9JZ1lBQms0YTVNdlBuOVlWeEpzNlh2aVFOZThJZVN6Y2xMR1dNV0dXOFRFTnBaMWJwRkNxa2FiRQpTN0cvdUVNMGtkaGhnYVpnVXhpK1JZUUhQcWhtNk1PZGdScWJpeTIxUDBOSFRFVktyaWtZanZYZXdTQnFtZ0xVClBRaTg1ME9qczF3UGRZVFRoajVCT2JZd3o5aEpWbWJIVEhvUGgwSDRGZGphMW9wY1M1ZXRvSGtOWU95MzdTbzgKQ2tzVjZzNnVyN3pVcWE5RlRMTXJNVnZhN2pvRHRzV2JXSjhsM2pheS9PSEV3UlI5RFNvTHVhYlppK2tWekZGUwp2eGRDTU52VzJEMmNSdzNHWW1HMGk4cXMxMXRsalFMTEV0S2EyWXJBZERSRXlFUFlKR1NYSjJDUXhqbGRpMzYrCmlHYitzNkExWVNCNzRxYldkbVcxWktqcGFPZmtmclRBZ3FocUc5UURrd2hPSk5CblVDUTBpZVpGYXV3MUZJM04KS0c1WEZSMzdKR05EL1luTGxCS1gzVzNMSGVIY1hTYUphYzYxOHFHbzgxVFduVzA2MVMzTGRVRWcyWGJ0SXJPKworNEdlNDlJbXRSTUFrcmhUUjAzMXc3ZDVnVXJtZWxCcTNzaVBmUmFkYmJ2OUM1VENHOG4zVDM1VkpLNFcybEduCkl5WUFzc09wYWxyN1Q5TmVuTzUxcUJmK2gyTjVVWitTVDV0TkYwM2s5enpKdGZORDZEcUNySHNDQXdFQUFUQU4KQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBQWNjblhwYUNJaVNzcG5oZ0tlTk9iSm9aaUJzSWNyTU4wVU1tSmVaagpSNkM2MHQzM1lEZDhXR2VhOW91WmVUZEFYOFIxYTlZOVFtV3JMMnpUTXIwbEwxdkRleXd0eUtjTFloVmFZaHUrCi9ibVFKTjJ5TnhWdU9ONkxtbkhBUFBFdjBtc3RWM1JuQXVxYlcvTm5DU0ZkUnFsSmlYT2hRLzlQUHJUUDZzck8KT2QwVHJ6VkE3RXlQT014TjJpSUdBcTJRemFBb3B6VDFVNmF4bnpHRmZ6aTZVSGlRYURSbGhuODhGUEpNT3JMUQpyS3NlUkk4MUtIaGptZG5uOFdlWC9BaGZWSk8wejZ2TU1xRGx5QmlSUmV3VmVQcjZTejl5T2RCQVZlNFUzSDdHCmdDV3p2akEzYkxjZEpobUw4dHQvVFpFcndMblFDd2Izc3pMODNSSDl0dXIzaWdwQnJoUzlWWnM4ZldyeWY0MDgKNnU0dWd3Y1luT0NpaGtwMk9ESjVtOThCbmdZem1wT2NDZW1KTkg3WkJ1SWhDVkNjRitCejlBbTlRSjJXdzdFZApTeGNDcFQxY0hSd29Fd0I5a01ORmtpYlkzbFJBQ3BtTmQ3SWpWUU5ZNTlmeFBBdGo4cFlSYWJGa2JhSUtkT2FwCkxySE1jbmRCTXpMYkk1bGl1a2hQUTlGLyt5QkMybVRRZ0MvVzU5dThraW4yQTFRbDJRWUNXQzFYVWFXaXFxRVUKbVQ5SjU5L0dKZ3hIT1pNSXB4OERDK0ZYRDZkbEF1bUJLZzcxZnpsdjdNb3dKWWFFcFJEUlJubjU0YnQ4UmpVRwpRREpBV1VseHluSlF0dCtqdmFNR0lSZ2M2RkdJcUVVV1VzUU9wUDEwNFg4dUtPQWNSTjlmMWNSSGxTeUErTUp5Cnd1UT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=";
    public static final String BASE64_ENCRYPTION_PRIVATE_KEY =
            "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";
    public static final String SHA_1_THUMBPRINT = "SHA_1_THUMBPRINT";
    public static final String SHA_256_THUMBPRINT = "SHA_256_THUMBPRINT";
    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    @Mock ConfigurationService configurationService;
    private DcsCryptographyService underTest;

    @BeforeEach
    void setUp() {
        underTest = new DcsCryptographyService(configurationService);
    }

    @Test
    void shouldPreparePayloadForDcsRequest()
            throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException,
                    CertificateException, ParseException, JsonProcessingException {
        when(configurationService.getPrivateKey(PASSPORT_CRI_SIGNING_KEY))
                .thenReturn(getSigningPrivateKey());
        when(configurationService.makeThumbprints())
                .thenReturn(new Thumbprints(SHA_1_THUMBPRINT, SHA_256_THUMBPRINT));
        when(configurationService.getCertificate(DCS_ENCRYPTION_CERT))
                .thenReturn(getEncryptionCertificate());

        DcsPayload dcsPayload =
                new DcsPayload(
                        "PASSPORT_NUMBER",
                        "SURNAME",
                        List.of("FORENAMES"),
                        LocalDate.now(),
                        LocalDate.now());
        JWSObject preparedPayload = underTest.preparePayload(dcsPayload);

        JWSVerifier verifier =
                new RSASSAVerifier((RSAPublicKey) getSigningPublicKey(getSigningPrivateKey()));

        JWEObject encryptedContents = JWEObject.parse(preparedPayload.getPayload().toString());

        RSADecrypter rsaDecrypter = new RSADecrypter(getEncryptionPrivateKey());
        encryptedContents.decrypt(rsaDecrypter);

        JWSObject decryptedPassportDetails =
                JWSObject.parse(encryptedContents.getPayload().toString());

        assertTrue(decryptedPassportDetails.verify(verifier));
        String expected = objectMapper.writeValueAsString(dcsPayload);
        assertEquals(expected, decryptedPassportDetails.getPayload().toString());
    }

    @Test
    void shouldUnwrapDcsResponse()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    ParseException, JOSEException, JsonProcessingException {
        when(configurationService.getCertificate(DCS_SIGNING_CERT))
                .thenReturn(TestUtils.getDcsSigningCertificate(BASE64_DCS_SIGNING_CERT));
        when(configurationService.getPrivateKey(PASSPORT_CRI_ENCRYPTION_KEY))
                .thenReturn(getEncryptionPrivateKey());
        DcsResponse expectedDcsResponse =
                new DcsResponse(
                        UUID.randomUUID().toString(),
                        UUID.randomUUID().toString(),
                        false,
                        true,
                        null);
        String dcsResponse =
                generateDCSResponse(objectMapper.writeValueAsString(expectedDcsResponse));
        DcsSignedEncryptedResponse dcsResponseItem = new DcsSignedEncryptedResponse(dcsResponse);
        DcsResponse actualDcsResponse = underTest.unwrapDcsResponse(dcsResponseItem);

        assertEquals(expectedDcsResponse.getCorrelationId(), actualDcsResponse.getCorrelationId());
        assertEquals(expectedDcsResponse.getRequestId(), actualDcsResponse.getRequestId());
        assertEquals(expectedDcsResponse.isError(), actualDcsResponse.isError());
        assertEquals(expectedDcsResponse.isValid(), actualDcsResponse.isValid());
    }

    @Test
    void shouldThrowExceptionForInvalidOuterSignatureWhenUsingIncorrectCertificate()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException {
        when(configurationService.getCertificate(DCS_SIGNING_CERT))
                .thenReturn(TestUtils.getDcsSigningCertificate(BASE64_ENCRYPTION_PUBLIC_CERT));
        String payload = "some test data";
        String dcsResponse = generateDCSResponse(payload);
        DcsSignedEncryptedResponse dcsResponseItem = new DcsSignedEncryptedResponse(dcsResponse);

        IpvCryptoException thrownException =
                assertThrows(
                        IpvCryptoException.class,
                        () -> underTest.unwrapDcsResponse(dcsResponseItem));

        assertEquals("DCS Response Outer Signature invalid.", thrownException.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenFailingToDecryptWithInvalidPrivateKey()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException {
        when(configurationService.getCertificate(DCS_SIGNING_CERT))
                .thenReturn(TestUtils.getDcsSigningCertificate(BASE64_DCS_SIGNING_CERT));
        when(configurationService.getPrivateKey(PASSPORT_CRI_ENCRYPTION_KEY))
                .thenReturn(getSigningPrivateKey());
        String payload = "some test data";
        String dcsResponse = generateDCSResponse(payload);
        DcsSignedEncryptedResponse dcsResponseItem = new DcsSignedEncryptedResponse(dcsResponse);

        IpvCryptoException thrownException =
                assertThrows(
                        IpvCryptoException.class,
                        () -> underTest.unwrapDcsResponse(dcsResponseItem));

        assertTrue(thrownException.getMessage().startsWith("Cannot Decrypt DCS Payload:"));
    }

    @Test
    void shouldThrowExceptionForInvalidInnerSignatureWhenUsingIncorrectCertificate()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException {
        when(configurationService.getCertificate(DCS_SIGNING_CERT))
                .thenReturn(
                        TestUtils.getDcsSigningCertificate(BASE64_DCS_SIGNING_CERT),
                        TestUtils.getDcsSigningCertificate(BASE64_ENCRYPTION_PUBLIC_CERT));
        when(configurationService.getPrivateKey(PASSPORT_CRI_ENCRYPTION_KEY))
                .thenReturn(getEncryptionPrivateKey());

        String payload = "some test data";
        String dcsResponse = generateDCSResponse(payload);
        DcsSignedEncryptedResponse dcsResponseItem = new DcsSignedEncryptedResponse(dcsResponse);

        IpvCryptoException thrownException =
                assertThrows(
                        IpvCryptoException.class,
                        () -> underTest.unwrapDcsResponse(dcsResponseItem));

        assertEquals("DCS Response Inner Signature invalid.", thrownException.getMessage());
    }

    private String generateDCSResponse(String innerPayload)
            throws CertificateException, JOSEException, InvalidKeySpecException,
                    NoSuchAlgorithmException {
        JWSObject innerJwsObject = generateJwsForDCS(innerPayload);
        JWEObject encryptedPayload = generateDcsEncryptedResponse(innerJwsObject);
        JWSObject outerJwsObject = generateJwsForDCS(encryptedPayload.serialize());
        return outerJwsObject.serialize();
    }

    private JWSObject generateJwsForDCS(String payload)
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));
        jwsObject.sign(new RSASSASigner(getPrivateKey()));
        return jwsObject;
    }

    private JWEObject generateDcsEncryptedResponse(JWSObject toEncrypt)
            throws CertificateException, JOSEException {
        JWEHeader header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        JWEObject jwe = new JWEObject(header, new Payload(toEncrypt.serialize()));

        jwe.encrypt(new RSAEncrypter((RSAPublicKey) getCertificate().getPublicKey()));

        return jwe;
    }

    private Certificate getCertificate() throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(BASE64_ENCRYPTION_PUBLIC_CERT);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

    private PrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(
                        new PKCS8EncodedKeySpec(
                                Base64.getDecoder().decode(BASE64_DCS_SIGNING_KEY)));
    }

    private PublicKey getSigningPublicKey(RSAPrivateKey signingPrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) signingPrivateKey;
        RSAPublicKeySpec keySpec =
                new RSAPublicKeySpec(
                        rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private RSAPrivateKey getSigningPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (RSAPrivateKey)
                KeyFactory.getInstance("RSA")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(BASE64_SIGNING_PRIVATE_KEY)));
    }

    private PrivateKey getEncryptionPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(
                        new PKCS8EncodedKeySpec(
                                Base64.getDecoder().decode(BASE64_ENCRYPTION_PRIVATE_KEY)));
    }

    private Certificate getEncryptionCertificate() throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(BASE64_ENCRYPTION_PUBLIC_CERT);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }
}
