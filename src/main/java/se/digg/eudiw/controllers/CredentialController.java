package se.digg.eudiw.controllers;

import java.text.ParseException;
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.validation.Valid;
import jakarta.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.server.ResponseStatusException;
import se.digg.eudiw.component.ProofDecoder;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.CredentialParam;
import se.digg.eudiw.model.credentialissuer.CredentialResponse;
import se.digg.eudiw.model.credentialissuer.JwtProof;
import se.digg.eudiw.service.CredentialIssuerService;
import se.digg.eudiw.service.CredentialOfferService;
import se.digg.eudiw.service.DummyProofService;
import se.digg.eudiw.service.OpenIdFederationService;
import se.digg.wallet.datatypes.common.TokenIssuingException;
import se.oidc.oidfed.md.wallet.credentialissuer.WalletOAuthClientMetadata;

@RestController
public class CredentialController {

    private static final Logger logger = LoggerFactory.getLogger(CredentialController.class);

    private final OpenIdFederationService openIdFederationService;
    private final ProofDecoder proofDecoder;
    private final CredentialIssuerService credentialIssuerService;
    private final CredentialOfferService credentialOfferService;
    private final DummyProofService dummyProofService;

    private ObjectMapper objectMapper = new ObjectMapper();

    public CredentialController(@Autowired OpenIdFederationService openIdFederationService, @Autowired ProofDecoder proofDecoder, @Autowired CredentialIssuerService credentialIssuerService, @Autowired CredentialOfferService credentialOfferService, DummyProofService dummyProofService) {
        this.openIdFederationService = openIdFederationService;
        this.proofDecoder = proofDecoder;
        this.credentialIssuerService = credentialIssuerService;
        this.credentialOfferService = credentialOfferService;
        this.dummyProofService = dummyProofService;
    }

    @GetMapping("/demo-oidfed-client")
    String oidfedClientDemo() {
        try {
            return openIdFederationService.resolveWallet("1234567890").toJson(true);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("/credential")
    CredentialResponse credential(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody CredentialParam credential) throws TokenIssuingException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication.getPrincipal() instanceof Jwt) {

                // wallet proof in request from wallet
                Optional<JWK> proofJwk = Optional.empty();

                JwtProof jwtProof = credential.getProof();

                if (jwtProof != null && "jwt".equals(jwtProof.getProofType()) && jwtProof.getJwt() != null) {

                    try {
                        logger.info("proof jwt: {}", jwtProof.getJwt());
                        SignedJWT signedJWT = SignedJWT.parse(jwtProof.getJwt());
                        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
                        JWSHeader header = signedJWT.getHeader();
                        JWK jwk = header.getJWK();
                        if (jwk != null)  {
                            proofJwk = Optional.of(jwk);
                        }
                        else {
                            String kid = header.getKeyID();
                            if (StringUtils.hasText(kid)) {
                                if (kid.indexOf("#") > 0) {
                                    kid = kid.split("#")[0];
                                    proofJwk = dummyProofService.jwk(kid);
                                }
                            }
                        }
                        logger.info("jwk: {}", jwk);



                    } catch (ParseException e) {
                        logger.info("No proof is parsed in credential request");
                    }

                }

                // get registered wallet proof public key from federation
//                String clientId = jwt.getClaim("clientId");
//                WalletOAuthClientMetadata walletOAuthClientMetadata = openIdFederationService.resolveWallet(clientId);
//                Optional<JWK> jwk;
//                if (walletOAuthClientMetadata != null) {
//                    jwk = walletOAuthClientMetadata.getJwkSet().getKeys().stream().findFirst();
//                } else {
//                    jwk = Optional.empty();
//                }
//
//                if (jwk.isPresent() && proofJwk.isPresent()) {
//                    // TODO verify device proof is present in federation
//                    try {
//                        logger.info("Compare proof key with clientId: {} registered key in federation thumbprint: {} device proof thumbprint: {}",
//                                clientId,
//                                jwk.get().computeThumbprint(),
//                                proofJwk.get().computeThumbprint());
//                    } catch (JOSEException e) {
//                        logger.info("Compare proof key with clientId: {} registered key in federation", clientId);
//                    }
//                }

                if (proofJwk.isEmpty()) throw new TokenIssuingException("Missing valid proof");

                return new CredentialResponse(
                        credentialIssuerService.credential(
                                credential.getFormat(),
                                credential.getVct(),
                                proofJwk.get(),
                                jwt
                        )
                );
            }
        }
        //catch (ParseException parseException) {
        //    throw new TokenIssuingException("Could not parse proof jwk");
        //}
        catch (HttpClientErrorException.BadRequest badRequest) {
            logger.error("Bad request", badRequest);
            throw badRequest;
        }
        throw new ResponseStatusException(
                HttpStatus.NOT_FOUND, "Credential Not Found");
    }


    @GetMapping("/credential_offer/{credential_offer_id}")
    CredentialOfferParam credentialOffer(@PathVariable String credential_offer_id) {
        return credentialOfferService.credentialOffer(credential_offer_id);
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<String> handleIllegalArgumentException(ValidationException ex) {
        logger.info("Validation exception", ex);
        return new ResponseEntity<>("Global Error: " + ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, TokenIssuingException.class})
    public ResponseEntity<String> handleIllegalArgumentException(MethodArgumentNotValidException ex) {
        logger.info("Cannot issue credential", ex);
        String wwwAuthenticate = "";
        Nonce dPoPNonce = new Nonce();
        MultiValueMap<String, String> headers = MultiValueMap.fromSingleValue(Map.of(
                "WWW-Authenticate", wwwAuthenticate,
                "DPoP-Nonce", dPoPNonce.getValue()
        ));
        Map<String, Object> data = Map.of(
                "c_nonce", dPoPNonce.getValue(),
                "c_nonce_expires_in", 86400,
                "error", "invalid_proof",
                "error_description", "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."
        );
        try {
            return new ResponseEntity<>(objectMapper.writeValueAsString(data), headers, HttpStatus.BAD_REQUEST);
        } catch (JsonProcessingException e) {
            return handleGeneralException(ex);
        }
    }

    // Catch all other exceptions
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        logger.error("General exception in credential issuer", ex);
        return new ResponseEntity<>("An error occurred: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
