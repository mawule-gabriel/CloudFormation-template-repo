package org.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class LogUserCreationHandler implements RequestHandler<Map<String, Object>, String> {
    private static final Logger logger = LoggerFactory.getLogger(LogUserCreationHandler.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Region region;
    private final String secretName;

    public LogUserCreationHandler() {
        // Get region from environment variable with fallback
        String configuredRegion = System.getenv("CUSTOM_REGION");
        this.region = Region.of(configuredRegion != null ? configuredRegion : "us-west-2");

        // Get environment name with fallback
        String environment = System.getenv("ENVIRONMENT");
        if (environment == null) {
            environment = "dev";
        }

        // Construct secret name with v5 version
        this.secretName = String.format("OneTimePassword-v5-%s-%s", environment, region.id());
    }

    // Rest of the code remains the same
    @Override
    public String handleRequest(Map<String, Object> event, Context context) {
        try {
            logger.info("Received event: {}", event);

            // Extract email from event
            String email = extractEmailFromEvent(event);
            if (email == null) {
                logger.error("Email not found in event");
                return "Email not found in event";
            }

            // Get password from Secrets Manager
            String password = getPassword();
            if (password == null) {
                logger.error("Failed to retrieve password from Secrets Manager");
                return "Failed to retrieve password";
            }

            // Log the user creation details
            logger.info("New User Created:");
            logger.info("Email: {}", email);
            logger.info("Temporary Password: {}", password);

            return "User credentials logged successfully";

        } catch (Exception e) {
            logger.error("Error processing request: {}", e.getMessage(), e);
            return "Error processing request: " + e.getMessage();
        }
    }

    private String extractEmailFromEvent(Map<String, Object> event) {
        try {
            Map<String, Object> detail = (Map<String, Object>) event.get("detail");
            if (detail == null) {
                logger.error("Event detail is missing");
                return null;
            }

            Map<String, Object> requestParameters = (Map<String, Object>) detail.get("requestParameters");
            if (requestParameters == null) {
                logger.error("Request parameters are missing");
                return null;
            }

            Map<String, String> tags = (Map<String, String>) requestParameters.get("tags");
            if (tags == null) {
                logger.error("Tags are missing");
                return null;
            }

            String email = tags.get("email");
            if (email == null) {
                logger.error("Email tag is missing");
                return null;
            }

            return email;

        } catch (Exception e) {
            logger.error("Error extracting email: {}", e.getMessage(), e);
            return null;
        }
    }

    private String getPassword() {
        try (SecretsManagerClient secretsManager = SecretsManagerClient.builder()
                .region(region)
                .build()) {

            GetSecretValueRequest request = GetSecretValueRequest.builder()
                    .secretId(secretName)
                    .build();

            GetSecretValueResponse response = secretsManager.getSecretValue(request);
            JsonNode jsonNode = objectMapper.readTree(response.secretString());
            return jsonNode.get("password").asText();

        } catch (Exception e) {
            logger.error("Error retrieving password: {}", e.getMessage(), e);
            return null;
        }
    }
}