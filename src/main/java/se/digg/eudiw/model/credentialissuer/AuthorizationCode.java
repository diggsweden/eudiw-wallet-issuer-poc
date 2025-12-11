package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class AuthorizationCode {
  String issuerState;

  public AuthorizationCode() {
    issuerState = "";
  }

  public AuthorizationCode(String issuerState) {
    this.issuerState = issuerState;
  }

  public String getIssuerState() {
    return issuerState;
  }

  public void setIssuerState(String issuerState) {
    this.issuerState = issuerState;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((issuerState == null) ? 0 : issuerState.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    AuthorizationCode other = (AuthorizationCode) obj;
    if (issuerState == null) {
      if (other.issuerState != null)
        return false;
    } else if (!issuerState.equals(other.issuerState))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "AuthorizationCode [issuerState=" + issuerState + "]";
  }


}


