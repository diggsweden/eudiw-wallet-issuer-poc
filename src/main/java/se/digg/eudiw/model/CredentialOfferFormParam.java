package se.digg.eudiw.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import se.digg.eudiw.model.credentialissuer.CredentialFormatEnum;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CredentialOfferFormParam {
    boolean pidMsoMdoc;
    boolean pidSdJwtVc;
    boolean preAuthCodeFlow;
    String validationErrors;

    public CredentialOfferFormParam() {
        pidMsoMdoc = false;
        pidSdJwtVc = false;
        preAuthCodeFlow = false;
        validationErrors = "";
    }

    public CredentialOfferFormParam(boolean pidMsoMdoc, boolean pidSdJwtVc, boolean preAuthCodeFlow, String validationErrors) {
        this.pidMsoMdoc = pidMsoMdoc;
        this.pidSdJwtVc = pidSdJwtVc;
        this.preAuthCodeFlow = preAuthCodeFlow;
        this.validationErrors = validationErrors;
    }

    public boolean isPidMsoMdoc() {
        return pidMsoMdoc;
    }

    public void setPidMsoMdoc(boolean pidMsoMdoc) {
        this.pidMsoMdoc = pidMsoMdoc;
    }

    public boolean isPidSdJwtVc() {
        return pidSdJwtVc;
    }

    public void setPidSdJwtVc(boolean pidSdJwtVc) {
        this.pidSdJwtVc = pidSdJwtVc;
    }

    public boolean isPreAuthCodeFlow() {
        return preAuthCodeFlow;
    }

    public void setPreAuthCodeFlow(boolean preAuthCodeFlow) {
        this.preAuthCodeFlow = preAuthCodeFlow;
    }

    public String getValidationErrors() {
        return validationErrors;
    }

    public void setValidationErrors(String validationErrors) {
        this.validationErrors = validationErrors;
    }

    public List<String> listOfCredentials() {
        return Stream.of(
                isPidMsoMdoc() ? "eu.europa.ec.eudi.pid_mdoc" : null ,
                isPidSdJwtVc() ? "eu.europa.ec.eudi.pid_jwt_vc_json" : null)
                .filter(Objects::nonNull).toList();
    }

    public enum CredentialTypeEnum {
        @JsonProperty("eu.europa.ec.eudi.pid_jwt_vc_json")
        PID_SD_JWT_VC("eu.europa.ec.eudi.pid_jwt_vc_json"),
        @JsonProperty("eu.europa.ec.eudi.pid_mdoc")
        PID_MSO_MDOC("eu.europa.ec.eudi.pid_mdoc");

        private final String credentialType;

        CredentialTypeEnum(String credentialType) {
            this.credentialType = credentialType;
        }

        public String getCredentialType() {
            return credentialType;
        }

        public static CredentialTypeEnum fromString(String credentialType) {
            return Arrays.stream(values())
                    .filter(credFormat -> credFormat.credentialType.equalsIgnoreCase(credentialType))
                    .findFirst()
                    .orElse(null);
        }

    }
}
