package se.digg.eudiw.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.config.SignerConfig;
import se.digg.eudiw.service.MetadataService;
import se.digg.eudiw.service.OpenIdFederationService;
import se.oidc.oidfed.base.data.federation.EntityMetadataInfoClaim;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.EntityStatementDefinedParams;
import se.oidc.oidfed.base.data.federation.TrustMarkClaim;
import se.oidc.oidfed.md.entities.FederationEntityMetadata;
import se.oidc.oidfed.md.lang.LanguageObject;
import se.oidc.oidfed.md.wallet.credentialissuer.*;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

@RestController
public class MetadataController {

    private final OpenIdFederationService openIdFederationService;
    private final SignerConfig signer;
    private final EudiwConfig eudiwConfig;
    private final CredentialBundles credentialBundles;
    private final MetadataService metadataService;

    Logger logger = LoggerFactory.getLogger(MetadataController.class);

    public MetadataController(EudiwConfig eudiwConfig, OpenIdFederationService openIdFederationService, SignerConfig signer, CredentialBundles credentialBundles, MetadataService metadataService) {
        this.openIdFederationService = openIdFederationService;
        this.signer = signer;
        this.eudiwConfig = eudiwConfig;
        this.credentialBundles = credentialBundles;
        this.metadataService = metadataService;
    }

    @GetMapping("/.well-known/jwks.json")
    Map<String, Object> jwks() {
        final PkiCredential issuerCredential = credentialBundles.getCredential("issuercredential");
        return new JwkTransformerFunction().apply(issuerCredential).toJSONObject();
    }

    @GetMapping("/.well-known/openid-credential-issuer")
    CredentialIssuerMetadata metadata() throws CertificateEncodingException, JOSEException, JsonProcessingException {
        return metadataService.metadata();
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

            final EntityMetadataInfoClaim entityMetadataInfoClaim = EntityMetadataInfoClaim.builder()
                    .federationEntityMetadataObject(
                            FederationEntityMetadata.builder()
                                    .organizationName(LanguageObject.builder(String.class).defaultValue("DIGG").build())
                                    .build().toJsonObject())
                    .build();
                    entityMetadataInfoClaim.setMetadataClaimsObject("openid_credential_issuer", metadata().toJsonObject());
            final EntityStatementDefinedParams definedParams =
                    EntityStatementDefinedParams.builder()
                    .jwkSet(new JWKSet(signer.getPublicJwk()))
                    .metadata(
                            entityMetadataInfoClaim
                    )
                            .sourceEndpoint(String.format("%s/%s", eudiwConfig.getIssuerBaseUrl(), ".well-known/openid-federation"))
                            .authorityHints(eudiwConfig.getOpenidFederation().authorityHints())
                            .trustMarks(List.of(TrustMarkClaim.builder()
                                            .id(eudiwConfig.getOpenidFederation().trustMarkId())
                                            .trustMark(openIdFederationService.trustMark(eudiwConfig.getOpenidFederation().trustMarkId(), eudiwConfig.getOpenidFederation().subject()))
                                    .build()))
                            .build();

            String jwt = EntityStatement.builder()
                    .issuer(eudiwConfig.getIssuer())
                    .subject(eudiwConfig.getIssuer())
                    .issueTime(issCalendar.getTime())
                    .expriationTime(expCalendar.getTime())
                    .definedParams(definedParams)
                    .build(signer.getJwtSigningCredential(), null).getSignedJWT().serialize();

            return ResponseEntity.ok().body(jwt);
        } catch (JsonProcessingException | NoSuchAlgorithmException | JOSEException | CertificateEncodingException e) {
            logger.error("Could not create entity statement", e);
            return ResponseEntity.internalServerError().body("Could not create entity statement");
        }
    }

}
