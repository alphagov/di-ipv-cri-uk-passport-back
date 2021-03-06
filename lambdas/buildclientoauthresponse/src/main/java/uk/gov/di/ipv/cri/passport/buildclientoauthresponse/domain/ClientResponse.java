package uk.gov.di.ipv.cri.passport.buildclientoauthresponse.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ClientResponse {
    @JsonProperty private final ClientDetails client;

    @JsonCreator
    public ClientResponse(@JsonProperty(value = "client", required = true) ClientDetails client) {
        this.client = client;
    }

    public ClientDetails getClient() {
        return client;
    }
}
