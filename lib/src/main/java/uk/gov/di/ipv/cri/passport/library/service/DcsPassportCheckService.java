package uk.gov.di.ipv.cri.passport.library.service;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.DCS_RESPONSE_TABLE_NAME;

public class DcsPassportCheckService {
    private final DataStore<PassportCheckDao> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public DcsPassportCheckService(ConfigurationService configurationService) {
        this.dataStore =
                new DataStore<>(
                        configurationService.getEnvironmentVariable(DCS_RESPONSE_TABLE_NAME),
                        PassportCheckDao.class,
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()),
                        configurationService);
    }

    public DcsPassportCheckService(DataStore<PassportCheckDao> dataStore) {
        this.dataStore = dataStore;
    }

    public PassportCheckDao getDcsPassportCheck(String resourceId) {
        return dataStore.getItem(resourceId);
    }
}
