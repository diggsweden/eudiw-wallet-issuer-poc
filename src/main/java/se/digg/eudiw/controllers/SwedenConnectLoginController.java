package se.digg.eudiw.controllers;

import java.util.Base64;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.view.RedirectView;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import se.digg.eudiw.context.EudiwSessionSecurityContextRepository;
import se.swedenconnect.auth.commons.dto.ClientAuthRequest;
@RestController
public class SwedenConnectLoginController {

    Logger logger = LoggerFactory.getLogger(SwedenConnectLoginController.class);

    @Value("${eudiw.swedenconnect.base-url}")
    String swedencconnectBaseUri;
    @Value("${eudiw.swedenconnect.client}")
    String client;
    @Value("${eudiw.swedenconnect.return-base-url}")
    String returnBaseUrl;
   
    
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Autowired
    private EudiwSessionSecurityContextRepository contextRepository;

	@GetMapping("/auth/login")
	RedirectView login(HttpServletRequest request, HttpServletResponse response) {
        String authenticationId = UUID.randomUUID().toString();
        SecurityContext securityContext = SecurityContextHolder.getContext();

        logger.info("swedenconnectBaseUri: " + swedencconnectBaseUri);
        logger.info("client: " + client);
        logger.info("returnBaseUrl: " + returnBaseUrl);

        try {
            ClientAuthRequest authreq =  new ClientAuthRequest(authenticationId, client, returnBaseUrl + "/" + authenticationId);
            String encodedRequest = Base64.getEncoder().encodeToString(OBJECT_MAPPER.writeValueAsBytes(authreq));
            String authReqUrl = swedencconnectBaseUri + "?request=" + encodedRequest;

            this.contextRepository.addPendingContext(authenticationId, securityContext);        
            logger.info("SAVE CONTEXT" + securityContext.toString());
            contextRepository.saveContext(securityContext, request, null);
            logger.info("Redirect login to: " + authReqUrl + " ###### " + authreq.toString() + " ###### " + OBJECT_MAPPER.writeValueAsString(authreq));
            return new RedirectView(authReqUrl);
        }
        catch (JsonProcessingException e) {
            logger.error("Could not create swedenconnect authentication request", e);
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR, 
                "Internt serverfel"
            );
        }
    }

//    @GetMapping("/")
//    String foobar(HttpServletRequest request, HttpServletResponse response) {
//        SecurityContext securityContext = SecurityContextHolder.getContext();
//
//        return "foobar" + securityContext.getAuthentication().getPrincipal().toString();
//    }

}


