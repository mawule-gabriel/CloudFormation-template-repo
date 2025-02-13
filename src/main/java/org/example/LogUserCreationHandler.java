package org.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.*;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.s3.S3Client;

import java.util.Collections;
import java.util.Map;

public class LogUserCreationHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Region s3Region;
    private final S3Client s3Client;
    private final String secretName;

    public LogUserCreationHandler() {
        // Get S3 bucket region from environment variable
        String s3BucketRegion = System.getenv("S3_BUCKET_REGION");
        this.s3Region = Region.of(s3BucketRegion != null ? s3BucketRegion : "us-west-2");

        // Initialize S3 client with specific region
        this.s3Client = S3Client.builder()
                .region(s3Region)
                .build();

        // Get environment name from Lambda environment variable
        String environment = System.getenv("ENVIRONMENT");
        if (environment == null) {
            environment = "dev";
        }

        // Construct the secret name
        this.secretName = String.format("OneTimePassword-%s-%s", environment, s3Region.id());
    }


    public void handleRequest(Map<String, Object> event, Context context) {
        try (SecretsManagerClient secretsManager = SecretsManagerClient.create();
             CloudWatchLogsClient cloudWatchLogs = CloudWatchLogsClient.create()) {

            // Extract email from the event details
            Map<String, Object> detail = (Map<String, Object>) event.get("detail");
            String email = extractEmailFromRequestParameters(detail);

            if (email == null) {
                System.err.println("Email not found in event");
                return;
            }

            // Retrieve and parse the password from Secrets Manager
            String password = getPassword(secretsManager);

            // Log to CloudWatch
            logUserCreation(cloudWatchLogs, email, password);

        } catch (Exception e) {
            System.err.println("Error processing request: " + e.getMessage());
            throw new RuntimeException(e);
        } finally {
            // Close the S3 client
            s3Client.close();
        }
    }

    private String extractEmailFromRequestParameters(Map<String, Object> detail) {
        try {
            Map<String, Object> requestParameters = (Map<String, Object>) detail.get("requestParameters");
            if (requestParameters != null) {
                Map<String, String> tags = (Map<String, String>) requestParameters.get("tags");
                if (tags != null) {
                    return tags.get("email");
                }
            }
        } catch (Exception e) {
            System.err.println("Error extracting email: " + e.getMessage());
        }
        return null;
    }

    private String getPassword(SecretsManagerClient secretsManager) throws Exception {
        GetSecretValueRequest request = GetSecretValueRequest.builder()
                .secretId(secretName)  // Use the constructed secret name
                .build();

        GetSecretValueResponse response = secretsManager.getSecretValue(request);
        JsonNode jsonNode = objectMapper.readTree(response.secretString());
        return jsonNode.get("password").asText();
    }

    private void logUserCreation(CloudWatchLogsClient cloudWatchLogs, String email, String password) {
        try {
            // Get log group and stream names from environment variables
            String logGroupName = System.getenv("LOG_GROUP_NAME");
            String logStreamName = System.getenv("LOG_STREAM_NAME");

            InputLogEvent logEvent = InputLogEvent.builder()
                    .message("User Created: " + email + " | Password: " + password)
                    .timestamp(System.currentTimeMillis())
                    .build();

            PutLogEventsRequest logRequest = PutLogEventsRequest.builder()
                    .logGroupName(logGroupName)
                    .logStreamName(logStreamName)
                    .logEvents(Collections.singletonList(logEvent))
                    .build();

            cloudWatchLogs.putLogEvents(logRequest);
        } catch (CloudWatchLogsException e) {
            System.err.println("Error writing to CloudWatch: " + e.getMessage());
            throw e;
        }
    }
}