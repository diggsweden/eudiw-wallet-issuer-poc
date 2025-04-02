package se.digg.eudiw.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import se.digg.eudiw.model.credentialissuer.CredentialFormatEnum;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CredentialOfferFormParam {
    boolean preAuthCodeFlow;
    List<String> availableCredentials;
    List<String> selectedCredentials;
    String message;

    public CredentialOfferFormParam() {
        preAuthCodeFlow = false;
    }

    public CredentialOfferFormParam(boolean preAuthCodeFlow, List<String> availableCredentials, List<String> selectedCredentials, String message) {
        this.preAuthCodeFlow = preAuthCodeFlow;
        this.availableCredentials = availableCredentials;
        this.selectedCredentials = selectedCredentials;
        this.message = message;
    }

    public boolean isCompleteAndValid() {
        return selectedCredentials != null && !selectedCredentials.isEmpty();
    }

    public boolean isPreAuthCodeFlow() {
        return preAuthCodeFlow;
    }

    public void setPreAuthCodeFlow(boolean preAuthCodeFlow) {
        this.preAuthCodeFlow = preAuthCodeFlow;
    }

    public List<String> getAvailableCredentials() {
        return availableCredentials;
    }

    public void setAvailableCredentials(List<String> availableCredentials) {
        this.availableCredentials = availableCredentials;
    }

    public List<String> getSelectedCredentials() {
        return selectedCredentials;
    }

    public void setSelectedCredentials(List<String> selectedCredentials) {
        this.selectedCredentials = selectedCredentials;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof CredentialOfferFormParam that)) return false;
        return preAuthCodeFlow == that.preAuthCodeFlow && Objects.equals(availableCredentials, that.availableCredentials) && Objects.equals(selectedCredentials, that.selectedCredentials) && Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(preAuthCodeFlow, availableCredentials, selectedCredentials, message);
    }

    @Override
    public String toString() {
        return "CredentialOfferFormParam{" +
                "preAuthCodeFlow=" + preAuthCodeFlow +
                ", availableCredentials=" + availableCredentials +
                ", selectedCredentials=" + selectedCredentials +
                ", message='" + message + '\'' +
                '}';
    }

    public record RequestCredential(String credential, String logo, boolean selected) {
        public String getCredential() {
            return credential;
        }

        public boolean isSelected() {
            return selected;
        }


    }

}
