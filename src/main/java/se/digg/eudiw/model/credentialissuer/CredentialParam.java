package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.validation.constraints.NotNull;
import org.springframework.validation.annotation.Validated;

import java.util.Objects;

@Validated
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CredentialParam {
  CredentialFormatEnum format;
  @NotNull
  JwtProof proof;

  @NotNull
  String credentialConfigurationId;

  public CredentialParam() {
    this.format = CredentialFormatEnum.VC_SD_JWT;
    this.proof = null;
    this.credentialConfigurationId = null;
  }

  public CredentialParam(CredentialFormatEnum format, JwtProof proof,
      String credentialConfigurationId) {
    this.format = format;
    this.proof = proof;
    this.credentialConfigurationId = credentialConfigurationId;
  }

  public CredentialFormatEnum getFormat() {
    return format;
  }

  public void setFormat(CredentialFormatEnum format) {
    this.format = format;
  }

  public JwtProof getProof() {
    return proof;
  }

  public void setProof(JwtProof proof) {
    this.proof = proof;
  }

  public String getCredentialConfigurationId() {
    return credentialConfigurationId;
  }

  public void setCredentialConfigurationId(String credentialConfigurationId) {
    this.credentialConfigurationId = credentialConfigurationId;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof CredentialParam that))
      return false;
    return format == that.format && Objects.equals(proof,
        that.proof) && Objects.equals(credentialConfigurationId,
            that.credentialConfigurationId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(format, proof, credentialConfigurationId);
  }

  @Override
  public String toString() {
    return "CredentialParam{" +
        "format=" + format +
        ", proof=" + proof +
        ", credentialConfigurationId='" + credentialConfigurationId + '\'' +
        '}';
  }
}
