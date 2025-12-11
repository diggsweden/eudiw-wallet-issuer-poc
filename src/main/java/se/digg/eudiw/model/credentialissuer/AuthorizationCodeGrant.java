package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationCodeGrant implements Grant {
  String issuerState;
  String authorizationServer;


  public AuthorizationCodeGrant() {}

  public AuthorizationCodeGrant(String issuerState, String authorizationServer) {
    this.issuerState = issuerState;
    this.authorizationServer = authorizationServer;
  }

  public String getIssuerState() {
    return issuerState;
  }

  public void setIssuerState(String issuerState) {
    this.issuerState = issuerState;
  }

  public String getAuthorizationServer() {
    return authorizationServer;
  }

  public void setAuthorizationServer(String authorizationServer) {
    this.authorizationServer = authorizationServer;
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass())
      return false;
    AuthorizationCodeGrant that = (AuthorizationCodeGrant) o;
    return Objects.equals(issuerState, that.issuerState)
        && Objects.equals(authorizationServer, that.authorizationServer);
  }

  @Override
  public int hashCode() {
    return Objects.hash(issuerState, authorizationServer);
  }

  @Override
  public String toString() {
    return "AuthorizationCodeGrant{" +
        "issuerState='" + issuerState + '\'' +
        ", authorizationServer='" + authorizationServer + '\'' +
        '}';
  }
}
