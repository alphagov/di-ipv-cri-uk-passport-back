package uk.gov.di.ipv.cri.passport.issuecredential.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.ContraIndicators;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredential;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.EVIDENCE_TYPE_IDENTITY_CHECK;

class VerifiableCredentialTest {

    public static final String FAMILY_NAME = "familyName";
    public static final List<String> GIVEN_NAMES = List.of("givenNames");
    public static final String PASSPORT_NUMBER = "passportNumber";
    public static final LocalDate DATE_OF_BIRTH = LocalDate.of(1984, 9, 28);
    public static final LocalDate EXPIRY_DATE = LocalDate.of(2034, 9, 28);
    public static final String RESOURCE_ID = "resourceId";

    @Test
    void shouldConvertPassportCheckDaoToPassportCredentialIssuerResponse() {

        DcsPayload dcsPayload =
                new DcsPayload(
                        PASSPORT_NUMBER, FAMILY_NAME, GIVEN_NAMES, DATE_OF_BIRTH, EXPIRY_DATE);

        Evidence evidence = new Evidence(UUID.randomUUID().toString(), 4, 2, null);
        PassportCheckDao passportCheckDao =
                new PassportCheckDao(
                        RESOURCE_ID, dcsPayload, evidence, "test-user-id", "test-client-id");

        VerifiableCredential verifiableCredential =
                VerifiableCredential.fromPassportCheckDao(passportCheckDao);

        assertEquals(
                FAMILY_NAME,
                verifiableCredential
                        .getCredentialSubject()
                        .getName()
                        .get(0)
                        .getNameParts()
                        .get(1)
                        .getValue());
        assertEquals(
                GIVEN_NAMES.get(0),
                verifiableCredential
                        .getCredentialSubject()
                        .getName()
                        .get(0)
                        .getNameParts()
                        .get(0)
                        .getValue());
        assertEquals(
                DATE_OF_BIRTH.toString(),
                verifiableCredential.getCredentialSubject().getBirthDate().get(0).getValue());
        assertEquals(
                PASSPORT_NUMBER,
                verifiableCredential
                        .getCredentialSubject()
                        .getPassport()
                        .get(0)
                        .getDocumentNumber());
        assertEquals(
                EXPIRY_DATE.toString(),
                verifiableCredential.getCredentialSubject().getPassport().get(0).getExpiryDate());
        assertEquals(
                EVIDENCE_TYPE_IDENTITY_CHECK, verifiableCredential.getEvidence().get(0).getType());
        assertDoesNotThrow(
                () -> UUID.fromString(verifiableCredential.getEvidence().get(0).getTxn()));
        assertEquals(4, verifiableCredential.getEvidence().get(0).getStrengthScore());
        assertEquals(2, verifiableCredential.getEvidence().get(0).getValidityScore());
    }

    @Test
    void itDeserializesIntoTheCorrectJson() throws Exception {
        String expectedJson =
                "{\n"
                        + "  \"credentialSubject\" : {\n"
                        + "    \"name\" : [ {\n"
                        + "      \"nameParts\" : [ {\n"
                        + "        \"type\" : \"GivenName\",\n"
                        + "        \"value\" : \"givenNames\"\n"
                        + "      }, {\n"
                        + "        \"type\" : \"FamilyName\",\n"
                        + "        \"value\" : \"familyName\"\n"
                        + "      } ]\n"
                        + "    } ],\n"
                        + "    \"birthDate\" : [ {\n"
                        + "      \"value\" : \"1984-09-28\"\n"
                        + "    } ],\n"
                        + "    \"passport\" : [ {\n"
                        + "      \"documentNumber\" : \"passportNumber\",\n"
                        + "      \"expiryDate\" : \"2034-09-28\"\n"
                        + "    } ]\n"
                        + "  },\n"
                        + "  \"evidence\" : [ {\n"
                        + "    \"type\" : \"IdentityCheck\",\n"
                        + "    \"txn\" : \"b46cbad4-2680-433f-b12c-b09fc27f281f\",\n"
                        + "    \"strengthScore\" : 4,\n"
                        + "    \"validityScore\" : 2\n"
                        + "  } ],\n"
                        + "  \"type\" : [ \"VerifiableCredential\", \"IdentityCheckCredential\" ]\n"
                        + "}";

        DcsPayload dcsPayload =
                new DcsPayload(
                        PASSPORT_NUMBER, FAMILY_NAME, GIVEN_NAMES, DATE_OF_BIRTH, EXPIRY_DATE);
        Evidence evidence = new Evidence("b46cbad4-2680-433f-b12c-b09fc27f281f", 4, 2, null);
        PassportCheckDao passportCheckDao =
                new PassportCheckDao(
                        RESOURCE_ID, dcsPayload, evidence, "test-user-id", "test-client-id");

        VerifiableCredential verifiableCredential =
                VerifiableCredential.fromPassportCheckDao(passportCheckDao);

        assertEquals(
                expectedJson,
                new ObjectMapper()
                        .writerWithDefaultPrettyPrinter()
                        .writeValueAsString(verifiableCredential));
    }

    @Test
    void itDeserializesIntoTheCorrectJsonWhenThereAreContraIndicators() throws Exception {
        String expectedJson =
                "{\n"
                        + "  \"credentialSubject\" : {\n"
                        + "    \"name\" : [ {\n"
                        + "      \"nameParts\" : [ {\n"
                        + "        \"type\" : \"GivenName\",\n"
                        + "        \"value\" : \"givenNames\"\n"
                        + "      }, {\n"
                        + "        \"type\" : \"FamilyName\",\n"
                        + "        \"value\" : \"familyName\"\n"
                        + "      } ]\n"
                        + "    } ],\n"
                        + "    \"birthDate\" : [ {\n"
                        + "      \"value\" : \"1984-09-28\"\n"
                        + "    } ],\n"
                        + "    \"passport\" : [ {\n"
                        + "      \"documentNumber\" : \"passportNumber\",\n"
                        + "      \"expiryDate\" : \"2034-09-28\"\n"
                        + "    } ]\n"
                        + "  },\n"
                        + "  \"evidence\" : [ {\n"
                        + "    \"type\" : \"IdentityCheck\",\n"
                        + "    \"txn\" : \"b46cbad4-2680-433f-b12c-b09fc27f281f\",\n"
                        + "    \"strengthScore\" : 4,\n"
                        + "    \"validityScore\" : 2,\n"
                        + "    \"ci\" : [ \"D02\" ]\n"
                        + "  } ],\n"
                        + "  \"type\" : [ \"VerifiableCredential\", \"IdentityCheckCredential\" ]\n"
                        + "}";

        DcsPayload dcsPayload =
                new DcsPayload(
                        PASSPORT_NUMBER, FAMILY_NAME, GIVEN_NAMES, DATE_OF_BIRTH, EXPIRY_DATE);
        Evidence evidence =
                new Evidence(
                        "b46cbad4-2680-433f-b12c-b09fc27f281f",
                        4,
                        2,
                        List.of(ContraIndicators.D02));
        PassportCheckDao passportCheckDao =
                new PassportCheckDao(
                        RESOURCE_ID, dcsPayload, evidence, "test-user-id", "test-client-id");

        VerifiableCredential verifiableCredential =
                VerifiableCredential.fromPassportCheckDao(passportCheckDao);

        assertEquals(
                expectedJson,
                new ObjectMapper()
                        .writerWithDefaultPrettyPrinter()
                        .writeValueAsString(verifiableCredential));
    }
}
