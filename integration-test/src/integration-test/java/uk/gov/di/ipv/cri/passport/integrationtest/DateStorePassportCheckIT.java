package uk.gov.di.ipv.cri.passport.integrationtest;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.KeyAttribute;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DateStorePassportCheckIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(DateStorePassportCheckIT.class);
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().registerModule(new JavaTimeModule());

    private static final String RESOURCE_ID_PARAM = "resourceId";
    private static final String DCS_PAYLOAD_PARAM = "dcsPayload";
    private static final String EVIDENCE_PARAM = "evidence";
    private static final String USER_ID_PARAM = "userId";
    private static final List<String> createdItemIds = new ArrayList<>();

    private static DataStore<PassportCheckDao> dcsResponseDataStore;
    private static Table tableTestHarness;

    @BeforeAll
    public static void setUp() {
        String dcsResponseTableName = System.getenv("DCS_RESPONSE_TABLE_NAME");
        if (dcsResponseTableName == null) {
            throw new IllegalArgumentException(
                    "The environment variable 'DCS_RESPONSE_TABLE_NAME' must be provided to run this test");
        }

        ConfigurationService configurationService = new ConfigurationService();

        dcsResponseDataStore =
                new DataStore<>(
                        dcsResponseTableName,
                        PassportCheckDao.class,
                        DataStore.getClient(null),
                        configurationService);

        AmazonDynamoDB independentClient =
                AmazonDynamoDBClient.builder().withRegion("eu-west-2").build();
        DynamoDB testClient = new DynamoDB(independentClient);
        tableTestHarness = testClient.getTable(dcsResponseTableName);
    }

    @AfterAll
    public static void deleteTestItems() {
        for (String id : createdItemIds) {
            try {
                tableTestHarness.deleteItem(new KeyAttribute(RESOURCE_ID_PARAM, id));
            } catch (Exception e) {
                LOGGER.warn(
                        String.format(
                                "Failed to delete test data with %s of %s", RESOURCE_ID_PARAM, id));
            }
        }
    }

    @Test
    void shouldPutPassportCheckIntoTable() throws JsonProcessingException {
        PassportCheckDao passportCheckDao = createPassportCheckDao();

        dcsResponseDataStore.create(passportCheckDao);

        Item savedPassportCheck =
                tableTestHarness.getItem(RESOURCE_ID_PARAM, passportCheckDao.getResourceId());

        assertEquals(passportCheckDao.getResourceId(), savedPassportCheck.get(RESOURCE_ID_PARAM));

        String attributesJson =
                OBJECT_MAPPER.writeValueAsString(savedPassportCheck.get(DCS_PAYLOAD_PARAM));
        DcsPayload savedDcsPayload = OBJECT_MAPPER.readValue(attributesJson, DcsPayload.class);
        assertEquals(passportCheckDao.getDcsPayload().toString(), savedDcsPayload.toString());

        String gpg45ScoreJson =
                OBJECT_MAPPER.writeValueAsString(savedPassportCheck.get(EVIDENCE_PARAM));
        Evidence savedEvidence = OBJECT_MAPPER.readValue(gpg45ScoreJson, Evidence.class);
        assertEquals(passportCheckDao.getEvidence().toString(), savedEvidence.toString());

        String userId = savedPassportCheck.getString(USER_ID_PARAM);
        assertEquals(passportCheckDao.getUserId(), userId);
    }

    @Test
    void shouldGetPassportCheckDaoFromTable() throws JsonProcessingException {
        PassportCheckDao passportCheckDao = createPassportCheckDao();
        Item item = Item.fromJSON(OBJECT_MAPPER.writeValueAsString(passportCheckDao));
        tableTestHarness.putItem(item);

        PassportCheckDao result = dcsResponseDataStore.getItem(passportCheckDao.getResourceId());

        assertEquals(passportCheckDao.getResourceId(), result.getResourceId());
        assertEquals(
                passportCheckDao.getDcsPayload().toString(), result.getDcsPayload().toString());
        assertEquals(passportCheckDao.getEvidence().toString(), result.getEvidence().toString());
        assertEquals(passportCheckDao.getUserId(), result.getUserId());
        assertEquals(passportCheckDao.getClientId(), result.getClientId());
    }

    private PassportCheckDao createPassportCheckDao() {
        String resourceId = UUID.randomUUID().toString();
        DcsPayload dcsPayload =
                new DcsPayload(
                        "passport-number",
                        "surname",
                        List.of("family-name"),
                        LocalDate.of(1900, 1, 1),
                        LocalDate.of(2025, 2, 2));
        Evidence evidence = new Evidence(UUID.randomUUID().toString(), 4, 2, null);
        createdItemIds.add(resourceId);

        return new PassportCheckDao(
                resourceId, dcsPayload, evidence, "test-user-id", "test-client-id");
    }
}
