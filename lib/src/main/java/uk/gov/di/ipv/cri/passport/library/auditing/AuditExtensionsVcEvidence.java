package uk.gov.di.ipv.cri.passport.library.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;

import java.util.List;

public class AuditExtensionsVcEvidence implements AuditExtensions {
    @JsonProperty("iss")
    private final String iss;

    @JsonProperty("evidence")
    private final List<Evidence> evidence;

    public AuditExtensionsVcEvidence(
            @JsonProperty(value = "iss") String iss,
            @JsonProperty(value = "evidence") List<Evidence> evidence) {
        this.iss = iss;
        this.evidence = evidence;
    }
}
