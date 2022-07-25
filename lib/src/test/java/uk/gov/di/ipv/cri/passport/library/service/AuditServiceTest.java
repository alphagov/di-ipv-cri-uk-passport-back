package uk.gov.di.ipv.cri.passport.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {
    @Mock AmazonSQS mockSqs;
    @Mock ConfigurationService mockConfigurationService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AuditService auditService;

    @BeforeEach
    void setup() {
        when(mockConfigurationService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                .thenReturn("https://example-queue-url");

        auditService = new AuditService(mockSqs, mockConfigurationService);
    }

    @Test
    void shouldSendMessageToSqsQueue() throws JsonProcessingException, SqsException {
        auditService.sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_REQUEST_SENT);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        JsonNode messageBody =
                objectMapper.readTree(sqsSendMessageRequestCaptor.getValue().getMessageBody());
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_REQUEST_SENT.name(),
                messageBody.get("event_name").asText());
    }
}
