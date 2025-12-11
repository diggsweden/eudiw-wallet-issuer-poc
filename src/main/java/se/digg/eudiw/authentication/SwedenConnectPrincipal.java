package se.digg.eudiw.authentication;

import java.security.Principal;

import com.fasterxml.jackson.annotation.JsonIgnore;
import se.swedenconnect.auth.commons.idtoken.SubjAttributes;

public class SwedenConnectPrincipal implements Principal {

  private SubjAttributes subjAttributes;

  public SwedenConnectPrincipal() {}

  public SwedenConnectPrincipal(SubjAttributes subjAttributes) {
    this.subjAttributes = subjAttributes;
  }

  public SubjAttributes getSubjAttributes() {
    return subjAttributes;
  }

  public void setSubjAttributes(SubjAttributes subjAttributes) {
    this.subjAttributes = subjAttributes;
  }

  @Override
  @JsonIgnore
  public String getName() {
    return subjAttributes.getName();
  }

  @Override
  public String toString() {
    return subjAttributes.toString();
  }

}
