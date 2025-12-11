package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.validation.annotation.Validated;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@Validated
public class JwtProof {
  String proofType;

  @NotNull
  @NotBlank
  String jwt;

  public JwtProof() {
    this.jwt = "";
    this.proofType = "jwt";
  }

  public JwtProof(String jwt) {
    this.jwt = jwt;
    this.proofType = "jwt";
  }

  public String getJwt() {
    return jwt;
  }

  public void setJwt(@NotBlank @NotNull @Valid String jwt) {
    this.jwt = jwt;
  }

  public String getProofType() {
    return proofType;
  }

  public void setProofType(String proofType) {
    this.proofType = proofType;
  }



}
