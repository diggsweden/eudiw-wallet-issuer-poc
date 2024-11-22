package se.digg.eudiw.auth.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import se.digg.eudiw.auth.config.EudiwConfig;
import se.digg.eudiw.auth.config.SignerConfig;
import se.digg.wallet.metadata.*;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.EntityStatementDefinedParams;

@RestController
public class MetadataController {


    private final SignerConfig signer;
    private final EudiwConfig eudiwConfig;

    Logger logger = LoggerFactory.getLogger(MetadataController.class);

    public MetadataController(@Autowired EudiwConfig eudiwConfig, @Autowired SignerConfig signer) {
        this.signer = signer;
        this.eudiwConfig = eudiwConfig;
    }

    @GetMapping("/.well-known/openid-credential-issuer")
    CredentialIssuerMetadata metadata() {
        return CredentialIssuerMetadata.builder()
                .credentialIssuer(eudiwConfig.getIssuer())
                .authorizationServers(List.of(eudiwConfig.getAuthHost()))
                .credentialEndpoint(String.format("%s/credential", eudiwConfig.getCredentialHost()))
                .deferredCredentialEndpoint(String.format("%s/credential_deferred", eudiwConfig.getCredentialHost()))
                .notificationEndpoint(String.format("%s/notification", eudiwConfig.getCredentialHost()))
                .credentialResponseEncryption(CredentialResponseEncryption.builder()
                        .algValuesSupported(List.of("RS256", "ES256"))
                        .encValuesSupported(List.of("algo1", "algo2"))
                        .encryptionRequired(false)
                        .build())
                .batchCredentialIssuance(new BatchCredentialIssuance(100))
                .signedMetadata("signed_metadata_jwt")
                .display(Display.builder()
                        .name("Credential Issuer Name")
                        .locale("en")
                        .logo(new Display.Image("https://example.com/logo", "Logo"))
                        .build())
                .credentialConfiguration("VerifiablePortableDocumentA1", SdJwtCredentialConfiguration.builder()
                        .format("vc+sd-jwt")
                        .scope("VerifiablePortableDocumentA1")
                        .cryptographicBindingMethodsSupported(List.of("jwk"))
                        .credentialSigningAlgValuesSupported(List.of("ES256"))
                        //.proofType("jwt", new AbstractCredentialConfiguration.ProofType(List.of("ES256")))
                        .display(List.of(
                                Display.builder()
                                        .name("Portable Document A1")
                                        .locale("en")
                                        .backgroundColor("##12107c")
                                        .textColor("#FFFFFF")
                                        .build()))
                        .vct("VerifiablePortableDocumentA1")
                        .claim("given_name", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Given Name")
                                                .locale("en")
                                                .build(),
                                        Display.builder()
                                                .name("Förnamn")
                                                .locale("sv")
                                                .build(),
                                        Display.builder()
                                                .name("Vorname")
                                                .locale("de")
                                                .build()
                                ))
                                .build())
                        .claim("last_name", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Surname")
                                                .locale("en")
                                                .build(),
                                        Display.builder()
                                                .name("Efternamn")
                                                .locale("sv")
                                                .build(),
                                        Display.builder()
                                                .name("Nachname")
                                                .locale("de")
                                                .build()
                                ))
                                .build())
                        //.order(List.of("given_name","last_name"))
                        .build())
                .build();
    }

    @RequestMapping(value = "/.well-known/openid-federation", produces = "application/TODO_ENTITY_STATEMENT_TYPE")
    public ResponseEntity<String> entityStatement() {
        Date now = new Date();
        Calendar issCalendar = Calendar.getInstance();
        issCalendar.setTime(now);
        Calendar expCalendar = Calendar.getInstance();
        expCalendar.setTime(issCalendar.getTime());
        expCalendar.add(Calendar.HOUR_OF_DAY, 24); // todo config

        try {
            final EntityStatementDefinedParams.EntityStatementDefinedParamsBuilder paramsBuilder =
                    EntityStatementDefinedParams.builder()
                    .jwkSet(new JWKSet(signer.getPublicJwk()))
                    //.trustMarks(CollectionUtils.isEmpty(trustMarkClaims) ? null : trustMarkClaims)
                    //.authorityHints(this.entityProperties.getAuthorityHints())
                    //.metadata(this.getMetadata())
                    //.sourceEndpoint(this.getEntityIdentifier() + ENTITY_CONFIGURATION_PATH)
                    //.trustMarkIssuers(this.getTrustMarkIssuers(this.entityProperties.getTrustMarkIssuers()))
                    //.trustMarkOwners(this.getTrustMarkOwners(this.entityProperties.getTrustMarkOwners()))
                    ;

            String jwt = EntityStatement.builder()
                    .issuer(eudiwConfig.getIssuer())
                    .subject(eudiwConfig.getIssuer())
                    .issueTime(issCalendar.getTime())
                    .expriationTime(expCalendar.getTime())
                    .definedParams(paramsBuilder.build())
                    .build(signer.getJwtSigningCredential(), null).getSignedJWT().serialize();

            return ResponseEntity.ok().body(jwt);
        } catch (JsonProcessingException | NoSuchAlgorithmException | JOSEException e) {
            logger.error("Could not create entity statement", e);
            return ResponseEntity.internalServerError().body("Could not create entity statement");
        }
    }
}
