package se.digg.eudiw.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import se.digg.eudiw.config.EudiwConfig;
import se.swedenconnect.auth.commons.dto.ClientAuthRequest;

import java.util.Base64;
import java.util.UUID;

import static java.lang.String.format;

public class IdProxyRequestBuilder {

    Logger logger = LoggerFactory.getLogger(IdProxyRequestBuilder.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final String swedenconnectBaseUri;
    private final String client;
    private final String returnBaseUrl;

    public IdProxyRequestBuilder(EudiwConfig eudiwConfig) {
        swedenconnectBaseUri = eudiwConfig.getSwedenconnect().baseUrl();
        client = eudiwConfig.getSwedenconnect().client();
        returnBaseUrl = eudiwConfig.getSwedenconnect().returnBaseUrl();

        logger.info("swedenconnectBaseUri: " + swedenconnectBaseUri);
        logger.info("client: " + client);
        logger.info("returnBaseUrl: " + returnBaseUrl);
    }

    public String buildAuthenticationRequest() {
        logger.info("auth url generate authenticationId");

        String authenticationId = "XXXXXXX" + UUID.randomUUID().toString();
        return buildAuthenticationRequest(authenticationId);
    }

    public String buildAuthenticationRequest(String authenticationId) {
        try {
            ClientAuthRequest authreq = new ClientAuthRequest(authenticationId, client, returnBaseUrl + "/" + authenticationId);
            String encodedRequest = Base64.getEncoder().encodeToString(OBJECT_MAPPER.writeValueAsBytes(authreq));
            String url = format("%s?request=%s", swedenconnectBaseUri, encodedRequest);
            logger.info("auth url: {}", url);

            return url;

        } catch (JsonProcessingException e) {
            logger.error("Could not create swedenconnect authentication request", e);
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "Internt serverfel"
            );
        }
    }
}