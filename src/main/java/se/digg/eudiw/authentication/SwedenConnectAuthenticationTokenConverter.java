package se.digg.eudiw.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.web.authentication.AuthenticationConverter;
import se.digg.eudiw.context.EudiwSessionSecurityContextRepository;


public class SwedenConnectAuthenticationTokenConverter implements AuthenticationConverter {

  Logger logger = LoggerFactory.getLogger(SwedenConnectAuthenticationTokenConverter.class);

  private final EudiwSessionSecurityContextRepository securityContextRepository;

  public SwedenConnectAuthenticationTokenConverter(
      @Autowired EudiwSessionSecurityContextRepository securityContextRepository) {
    this.securityContextRepository = securityContextRepository;
  }

  @Override
  public Authentication convert(HttpServletRequest request) {
    DeferredSecurityContext deferredSecurityContext =
        securityContextRepository.loadDeferredContext(request);
    Authentication auth = deferredSecurityContext.get().getAuthentication();
    logger.info("Loaded security context authentication {}", auth);
    return auth;
  }
}
