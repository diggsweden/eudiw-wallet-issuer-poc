package se.digg.eudiw.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import se.swedenconnect.auth.commons.dto.ClientAuthResponse;

public class SwedenConnectAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

  private final Object principal;

  private ClientAuthResponse credentials;

  public SwedenConnectAuthenticationToken(Object principal, ClientAuthResponse credentials) {
    super(null);
    this.principal = principal;
    this.credentials = credentials;
    setAuthenticated(false);
  }

  public SwedenConnectAuthenticationToken(Object principal, ClientAuthResponse credentials,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.principal = principal;
    this.credentials = credentials;
    super.setAuthenticated(true); // must use super, as we override
  }

  public static SwedenConnectAuthenticationToken unauthenticated(Object principal,
      ClientAuthResponse credentials) {
    return new SwedenConnectAuthenticationToken(principal, credentials);
  }

  public static SwedenConnectAuthenticationToken authenticated(Object principal,
      ClientAuthResponse credentials,
      Collection<? extends GrantedAuthority> authorities) {
    return new SwedenConnectAuthenticationToken(principal, credentials, authorities);
  }

  @Override
  public ClientAuthResponse getCredentials() {
    return this.credentials;
  }

  @Override
  public Object getPrincipal() {
    return this.principal;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    Assert.isTrue(!isAuthenticated,
        "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
    super.setAuthenticated(false);
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.credentials = null;
  }

}
