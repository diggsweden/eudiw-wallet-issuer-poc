package se.digg.eudiw.controllers;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.service.ParCacheService;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/oauth2/par")
public class ParController {

    private static final Logger logger = LoggerFactory.getLogger(ParController.class);
    private final ParCacheService parRequestStore;
    private final int PAR_REQUEST_TTL;

    public ParController(@Autowired ParCacheService parRequestStore, @Autowired EudiwConfig eudiwConfig) {
        PAR_REQUEST_TTL = 600; // todo PAR config
        this.parRequestStore = parRequestStore;
    }

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes =  MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> handleParRequest(@RequestBody MultiValueMap<String, String> requestParams) {
        // Validate incoming parameters
       /* if (!requestParams.containsKey("client_id")) {
            return ResponseEntity.badRequest();
        }*/

        // Generate a unique URN as the request_uri
        String requestUri = "urn:example:request_uri:" + UUID.randomUUID();
        logger.info("Foo");
        // Store the authorization request parameters
        requestParams.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        parRequestStore.saveParParams(requestUri, requestParams, PAR_REQUEST_TTL);

        logger.info("Foo2");

        ResponseEntity<Map<String, Object>> response = ResponseEntity
                .status(HttpStatus.OK)
                .header("Custom-Header", "Custom-Value")
                .body(Map.of(
                        "request_uri", requestUri,
                        "expires_in", PAR_REQUEST_TTL // Expiration in seconds
                ));

        logger.info("Foo3 {}", response.getBody());
        return response;
        // Return the request_uri and expiration time
        //return ResponseEntity.ok().header("Custom-Header", "foo").body("BAR");
        /*Map.of(
                "request_uri", requestUri,
                "expires_in", PAR_REQUEST_TTL // Expiration in seconds
        ));*/
    }

    // Helper method to retrieve stored parameters by request_uri
    public MultiValueMap<String, String> getParRequest(String requestUri) {
        return parRequestStore.loadParParamsAndRemoveFromCache(requestUri);
    }
}
