package se.swedenconnect.auth.commons.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import se.swedenconnect.auth.commons.idtoken.DisoUI;

/**
 * Data record class for an origin request for user authentication
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientAuthRequest {

  String client;
  String idp;
  String idpAlias;
  String returnUrl;
  Boolean forceAuth;
  Boolean silent;
  List<String> loa;
  List<String> profile;
  String id;
  Boolean discovery;
  DisoUI ui;

  public ClientAuthRequest(String client, String idp, String idpAlias, String returnUrl,
      Boolean forceAuth,
      Boolean silent, List<String> loa, List<String> profile, String id, Boolean discovery,
      DisoUI ui) {
    this.client = client;
    this.idp = idp;
    this.idpAlias = idpAlias;
    this.returnUrl = returnUrl;
    this.forceAuth = forceAuth;
    this.silent = silent;
    this.loa = loa;
    this.profile = profile;
    this.id = id;
    this.discovery = discovery;
    this.ui = ui;
  }

  public ClientAuthRequest(String id, String client, String returnUrl) {
    this.id = id;
    this.returnUrl = returnUrl;
    this.client = client;
    this.discovery = null;
    this.forceAuth = null;
    this.idp = null;
    this.idpAlias = null;
    this.loa = null;
    this.profile = null;
    this.silent = null;
    this.ui = null;
  }

  public String getClient() {
    return client;
  }

  public void setClient(String client) {
    this.client = client;
  }

  public String getIdp() {
    return idp;
  }

  public void setIdp(String idp) {
    this.idp = idp;
  }

  public String getIdpAlias() {
    return idpAlias;
  }

  public void setIdpAlias(String idpAlias) {
    this.idpAlias = idpAlias;
  }

  public String getReturnUrl() {
    return returnUrl;
  }

  public void setReturnUrl(String returnUrl) {
    this.returnUrl = returnUrl;
  }

  public Boolean getForceAuth() {
    return forceAuth;
  }

  public void setForceAuth(Boolean forceAuth) {
    this.forceAuth = forceAuth;
  }

  public Boolean getSilent() {
    return silent;
  }

  public void setSilent(Boolean silent) {
    this.silent = silent;
  }

  public List<String> getLoa() {
    return loa;
  }

  public void setLoa(List<String> loa) {
    this.loa = loa;
  }

  public List<String> getProfile() {
    return profile;
  }

  public void setProfile(List<String> profile) {
    this.profile = profile;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public Boolean getDiscovery() {
    return discovery;
  }

  public void setDiscovery(Boolean discovery) {
    this.discovery = discovery;
  }

  public DisoUI getUi() {
    return ui;
  }

  public void setUi(DisoUI ui) {
    this.ui = ui;
  }


}
