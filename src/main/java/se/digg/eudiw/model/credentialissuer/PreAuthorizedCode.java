package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class PreAuthorizedCode {
  String preAuthorizedCode;
  boolean userPinRequired;

  public PreAuthorizedCode() {
    preAuthorizedCode = "";
    userPinRequired = false;
  }

  public PreAuthorizedCode(String preAuthorizedCode, boolean userPinRequired) {
    this.preAuthorizedCode = preAuthorizedCode;
    this.userPinRequired = userPinRequired;
  }

  public String getPreAuthorizedCode() {
    return preAuthorizedCode;
  }

  public void setPreAuthorizedCode(String preAuthorizedCode) {
    this.preAuthorizedCode = preAuthorizedCode;
  }

  public boolean isUserPinRequired() {
    return userPinRequired;
  }

  public void setUserPinRequired(boolean userPinRequired) {
    this.userPinRequired = userPinRequired;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((preAuthorizedCode == null) ? 0 : preAuthorizedCode.hashCode());
    result = prime * result + (userPinRequired ? 1231 : 1237);
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
    PreAuthorizedCode other = (PreAuthorizedCode) obj;
    if (preAuthorizedCode == null) {
      if (other.preAuthorizedCode != null)
        return false;
    } else if (!preAuthorizedCode.equals(other.preAuthorizedCode))
      return false;
    if (userPinRequired != other.userPinRequired)
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "PreAuthorizedCode [preAuthorizedCode=" + preAuthorizedCode + ", userPinRequired="
        + userPinRequired
        + "]";
  }


}
