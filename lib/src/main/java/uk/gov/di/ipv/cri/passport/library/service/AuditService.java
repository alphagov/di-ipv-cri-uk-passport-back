package uk.gov.di.ipv.cri.passport.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEvent;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;

import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class AuditService {
    private final AmazonSQS sqs;
    private final String queueUrl;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public AuditService(AmazonSQS sqs, ConfigurationService configurationService) {
        this.sqs = sqs;
        queueUrl = configurationService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
    }

    public static AmazonSQS getDefaultSqsClient() {
        return AmazonSQSClientBuilder.defaultClient();
    }

    public void sendAuditEvent(AuditEventTypes eventType) throws SqsException {
        sendAuditEvent(new AuditEvent(eventType, null, null, null, null));
    }

    public void sendAuditEvent(AuditEvent auditEvent) throws SqsException {
        try {
            SendMessageRequest sendMessageRequest =
                    new SendMessageRequest()
                            .withQueueUrl(queueUrl)
                            .withMessageBody(objectMapper.writeValueAsString(auditEvent));

            sqs.sendMessage(sendMessageRequest);
        } catch (JsonProcessingException e) {
            throw new SqsException(e);
        }
    }
}
