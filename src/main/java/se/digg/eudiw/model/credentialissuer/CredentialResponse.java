package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CredentialResponse {
  private String credential;
  private List<Credential> credentials;
  private String cNonce;
  private String cNonceExpiresIn;

  public CredentialResponse() {
    credentials = new ArrayList<>();
  }

  public CredentialResponse(String credential) {
    this.credential = credential;
    this.credentials = List.of(new Credential(credential));
  }

  public CredentialResponse(String credential, String cNonce, String cNonceExpiresIn) {
    this.credentials = List.of(new Credential(credential));
    this.cNonce = cNonce;
    this.cNonceExpiresIn = cNonceExpiresIn;
  }

  public String getCredential() {
    return credential;
  }

  public void setCredential(String credential) {
    this.credential = credential;
  }

  public List<Credential> getCredentials() {
    return credentials;
  }

  public void setCredentials(List<Credential> credentials) {
    this.credentials = credentials;
  }

  public String getcNonce() {
    return cNonce;
  }

  public void setcNonce(String cNonce) {
    this.cNonce = cNonce;
  }

  public String getcNonceExpiresIn() {
    return cNonceExpiresIn;
  }

  public void setcNonceExpiresIn(String cNonceExpiresIn) {
    this.cNonceExpiresIn = cNonceExpiresIn;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof CredentialResponse that))
      return false;
    return Objects.equals(credentials, that.credentials) && Objects.equals(cNonce,
        that.cNonce) && Objects.equals(cNonceExpiresIn, that.cNonceExpiresIn);
  }

  @Override
  public int hashCode() {
    return Objects.hash(credentials, cNonce, cNonceExpiresIn);
  }

  @Override
  public String toString() {
    return "CredentialResponse{" +
        "credentials=" + credentials +
        ", cNonce='" + cNonce + '\'' +
        ", cNonceExpiresIn='" + cNonceExpiresIn + '\'' +
        '}';
  }
}

