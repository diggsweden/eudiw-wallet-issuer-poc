package se.digg.eudiw.auth.controllers;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;

import org.springframework.web.client.RestTemplate;
import se.digg.eudiw.ApiClient;
import se.digg.eudiw.auth.config.EudiwConfig;
import se.digg.eudiw.auth.config.SignerConfig;
import se.digg.eudiw.client.DefaultApi;
import se.digg.eudiw.credentialissuer.model.Address;
import se.digg.eudiw.credentialissuer.model.CredentialOfferParam;
import se.digg.eudiw.credentialissuer.model.CredentialParam;
import se.digg.eudiw.credentialissuer.util.PidBuilder;

@RestController
public class CredentialController {

	private final EudiwConfig eudiwConfig;

	private final RestTemplate restTemplate;

	private final SignerConfig signerConfig;

	public CredentialController(@Autowired EudiwConfig eudiwConfig, @Autowired RestTemplate restTemplate, @Autowired SignerConfig signerConfig) {
		this.eudiwConfig = eudiwConfig;
		this.restTemplate = restTemplate;
		this.signerConfig = signerConfig;
	}


	@GetMapping("/demo-oidfed-client")
	String oidfedClientDemo() {
		ApiClient client = new ApiClient(restTemplate);
		client.setBasePath(eudiwConfig.getOidFederationBaseUrl());
		DefaultApi api = new DefaultApi(client);
		return api.nameResolveGet(
				"wallet-provider",
				"https://local.dev.swedenconnect.se/wallets/1234567890",
				"https://local.dev.swedenconnect.se:9040/oidfed/wallet-provider",
				null);
	}


	@GetMapping("/demo-credential")
	String demoCredential() {
        try {
			return new PidBuilder(eudiwConfig.getIssuer(), signerConfig)
                        .withExp(eudiwConfig.getExpHours())
                        .withVcType("IdentityCredential")
                        .addSelectiveDisclosure("given_name", "John")
                        .addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"))
                        .build();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
 
    }

    @PostMapping("/credential")
	String credential(@AuthenticationPrincipal Jwt jwt, @RequestBody CredentialParam credential) { // @AuthenticationPrincipal Jwt jwt,
        try {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication.getPrincipal() instanceof Jwt) {
				// TODO - get PID data from ID token and authentic source (t.ex. skatteverket)
				return new PidBuilder(eudiwConfig.getIssuer(), signerConfig)
                        .withExp(eudiwConfig.getExpHours())
                        .withVcType("https://attestations.eudiw.se/se_pid")
                        .addSelectiveDisclosure("given_name", jwt.getClaim("givenName"))
                        .addSelectiveDisclosure("last_name", jwt.getClaim("surname"))
						.addSelectiveDisclosure("birthdate", jwt.getClaim("birthDate"))
                        //.addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"))
                        .build();
			}
			
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
		return null;
    }

    @GetMapping("/credential_offer")
    Map<String, Object> credentialOffer(@RequestParam("credential_offer") CredentialOfferParam credentialOffer) {
        try {
			return Map.of("todo", "foobar");
		} catch(Exception e) {
			throw new RuntimeException(e);
		}

    }

}