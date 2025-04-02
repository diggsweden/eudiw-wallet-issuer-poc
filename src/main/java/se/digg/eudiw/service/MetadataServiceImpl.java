package se.digg.eudiw.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.springframework.stereotype.Service;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.config.SignerConfig;
import se.digg.eudiw.controllers.MetadataController;
import se.oidc.oidfed.md.wallet.credentialissuer.*;

import java.security.cert.CertificateEncodingException;
import java.util.List;

@Service
public class MetadataServiceImpl implements MetadataService {

    private EudiwConfig eudiwConfig;
    private final SignerConfig signer;

    MetadataServiceImpl(EudiwConfig eudiwConfig, SignerConfig signer) {
        this.eudiwConfig = eudiwConfig;
        this.signer = signer;
    }

    @Override
    public CredentialIssuerMetadata metadata() throws CertificateEncodingException, JOSEException, JsonProcessingException {
        CredentialIssuerMetadata.CredentialIssuerMetadataBuilder metadataBuilder = CredentialIssuerMetadata.builder()
                .credentialIssuer(eudiwConfig.getIssuer())
                .authorizationServers(List.of(eudiwConfig.getAuthHost()))
                .credentialEndpoint(String.format("%s/credential", eudiwConfig.getCredentialHost()))
                .deferredCredentialEndpoint(String.format("%s/credential_deferred", eudiwConfig.getCredentialHost()))
                .notificationEndpoint(String.format("%s/notification", eudiwConfig.getCredentialHost()))
                //.batchCredentialIssuance(new BatchCredentialIssuance(100))
                .display(List.of(
                        Display.builder()
                                .name("DIGG issuer")
                                .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                .locale("en")
                                .build(),
                        Display.builder()
                                .name("DIGG utfärdare")
                                .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                .locale("sv")
                                .build(),
                        Display.builder()
                                .name("DIGG aussteller")
                                .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                .locale("de")
                                .build()
                ))
                .credentialConfiguration("eu.europa.ec.eudi.pid_mdoc", IsoMdlCredentialConfiguration.builder()
                        .claim("eu.europa.ec.eudi.pid.1", "given_name", Claim.builder()
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
                        .claim("eu.europa.ec.eudi.pid.1", "last_name", Claim.builder()
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
                        .claim("eu.europa.ec.eudi.pid.1", "issuance_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date")
                                .display(List.of(
                                        Display.builder()
                                                .name("Date (and possibly time) when the PID was issued")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "issuing_country", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "issuing_authority", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Name of the administrative authority that has issued this PID instance, or the ISO 3166 Alpha-2 country code of the respective Member State if there is no separate authority authorized to issue PIDs")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "expiry_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date")
                                .display(List.of(
                                        Display.builder()
                                                .name("Expiry date")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "birth_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date") // TODO kolla hur det ska formateras
                                .display(List.of(
                                        Display.builder()
                                                .name("Date of Birth")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "age_over_15", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 15")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "age_over_15", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 16")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "age_over_18", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(true)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 18")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "age_over_20", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 20")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "age_over_65", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 65")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("eu.europa.ec.eudi.pid.1", "age_in_years", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(true)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age in years")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .format("mso_mdoc")
                        .doctype("eu.europa.ec.eudi.pid.1")
                        .scope("eu.europa.ec.eudi.pid.1")
                        .credentialSigningAlgValuesSupported(List.of("ES256"))
                        .cryptographicBindingMethodsSupported(List.of("jwk", "cose_key"))
                        .proofType("cwt", MetadataServiceImpl.ProofTypeWrapper.createProofType(List.of("ES256")))
                        .proofType("jwt", MetadataServiceImpl.ProofTypeWrapper.createProofType(List.of("ES256")))
                        .display(List.of(
                                Display.builder()
                                        .name("Person Identification Data SE (mdoc)")
                                        .locale("en")
                                        .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                        .build(),
                                Display.builder()
                                        .name("Personidentifieringsdata SE (mdoc)")
                                        .locale("sv")
                                        .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                        .build(),
                                Display.builder()
                                        .name("Personenidentifikationsdaten SE (mdoc)")
                                        .locale("de")
                                        .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                        .build()
                        ))
                        .build())
                .credentialConfiguration("eu.europa.ec.eudi.pid_jwt_vc_json", SdJwtCredentialConfiguration.builder()
                        .format("vc+sd-jwt")
                        .scope("eu.europa.ec.eudi.pid.1")
                        .cryptographicBindingMethodsSupported(List.of("jwk"))
                        .credentialSigningAlgValuesSupported(List.of("ES256"))
                        .proofType("jwt", MetadataServiceImpl.ProofTypeWrapper.createProofType(List.of("ES256")))
                        .display(List.of(
                                Display.builder()
                                        .name("Person Identification Data SE")
                                        .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                        .locale("en")
                                        .build(),
                                Display.builder()
                                        .name("Personidentifieringsdata SE")
                                        .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                        .locale("sv")
                                        .build(),
                                Display.builder()
                                        .name("Personenidentifikationsdaten SE")
                                        .logo(new Display.Image(String.format("%s/images/digg_logo.jpeg", eudiwConfig.getIssuerBaseUrl()), "DIGG logotype"))
                                        .locale("de")
                                        .build()
                        ))
                        .vct("urn:eu.europa.ec.eudi:pid:1")
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
                        // family_name is not specified in ARF, however it is the IANA name and should be present in sd jwt vc https://www.iana.org/assignments/jwt/jwt.xhtml#claims
                        .claim("family_name", Claim.builder()
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
                        .claim("issuance_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date")
                                .display(List.of(
                                        Display.builder()
                                                .name("Date (and possibly time) when the PID was issued")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("issuing_country", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("issuing_authority", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Name of the administrative authority that has issued this PID instance, or the ISO 3166 Alpha-2 country code of the respective Member State if there is no separate authority authorized to issue PIDs")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("expiry_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date")
                                .display(List.of(
                                        Display.builder()
                                                .name("Expiry date")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("birth_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date") // TODO kolla hur det ska formateras
                                .display(List.of(
                                        Display.builder()
                                                .name("Date of Birth")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        // birthdate is not specified in ARF, however it is the IANA name and should be present in sd jwt vc https://www.iana.org/assignments/jwt/jwt.xhtml#claims
                        .claim("birthdate", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date") // TODO kolla hur det ska formateras
                                .display(List.of(
                                        Display.builder()
                                                .name("Date of Birth")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("age_over_15", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 15")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("age_over_16", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 16")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("age_over_18", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(true)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 18")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("age_over_20", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 20")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("age_over_65", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(false)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age over 65")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("age_in_years", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(true)
                                .display(List.of(
                                        Display.builder()
                                                .name("Age in years")
                                                .locale("en")
                                                .build()
                                ))
                                .build())

                        //.order(List.of("given_name","last_name"))
                        .build()
                );
        if (eudiwConfig.isSignedMetaData()) {
            return metadataBuilder.buildWithSignedMetadata(signer.getJwtSigningCredential().getSigner(), JWSAlgorithm.ES256, signer.getJwtSigningCredential().getKid());
        }
        return metadataBuilder.build();
    }

    private static class ProofTypeWrapper extends AbstractCredentialConfiguration {
        public static ProofType createProofType(List<String> algValues) {
            return new ProofType(algValues);
        }
    }
}
