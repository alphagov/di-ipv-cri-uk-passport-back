package uk.gov.di.ipv.cri.passport.library.auditing;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.Instant;

@ExcludeFromGeneratedCoverageReport
public class AuditEvent {
    @JsonProperty private final long timestamp;

    @JsonProperty("event_name")
    private final AuditEventTypes eventName;

    @JsonProperty("component_id")
    private final String componentId;

    @JsonProperty private final AuditEventUser user;
    @JsonProperty private final AuditRestricted restricted;
    @JsonProperty private final AuditExtensions extensions;

    @JsonCreator
    public AuditEvent(
            @JsonProperty(value = "event_name", required = true) AuditEventTypes eventName,
            @JsonProperty(value = "component_id") String componentId,
            @JsonProperty(value = "user") AuditEventUser user,
            @JsonProperty(value = "restricted") AuditRestricted restricted,
            @JsonProperty(value = "extensions") AuditExtensions extensions) {
        this.timestamp = Instant.now().getEpochSecond();
        this.eventName = eventName;
        this.componentId = componentId;
        this.user = user;
        this.restricted = restricted;
        this.extensions = extensions;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public AuditEventTypes getEventName() {
        return eventName;
    }

    public String getComponentId() {
        return componentId;
    }

    public AuditEventUser getUser() {
        return user;
    }

    public AuditRestricted getRestricted() {
        return restricted;
    }

    public AuditExtensions getExtensions() {
        return extensions;
    }
}
