package uk.gov.di.ipv.cri.passport.library.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class AuditEventUser {

    @JsonProperty(value = "user_id")
    private final String userId;

    @JsonProperty(value = "session_id")
    private final String sessionId;

    public AuditEventUser(
            @JsonProperty(value = "user_id") String userId,
            @JsonProperty(value = "session_id") String sessionId) {
        this.userId = userId;
        this.sessionId = sessionId;
    }
}
