package se.digg.eudiw.context;

import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;

final class PathDeferredSecurityContext implements DeferredSecurityContext {

  private SecurityContext securityContext;


  public PathDeferredSecurityContext(SecurityContext context) {
    this.securityContext = context;
  }

  @Override
  public SecurityContext get() {
    return this.securityContext;
  }

  @Override
  public boolean isGenerated() {
    return false;
  }

}
