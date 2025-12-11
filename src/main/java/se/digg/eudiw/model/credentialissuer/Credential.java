package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Credential {

  private String credential;

  public Credential() {}

  public Credential(String credential) {
    this.credential = credential;
  }

  public String getCredential() {
    return credential;
  }

  public void setCredential(String credential) {
    this.credential = credential;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Credential that))
      return false;
    return Objects.equals(credential, that.credential);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(credential);
  }

  @Override
  public String toString() {
    return "Credential{" +
        "credential='" + credential + '\'' +
        '}';
  }
}
