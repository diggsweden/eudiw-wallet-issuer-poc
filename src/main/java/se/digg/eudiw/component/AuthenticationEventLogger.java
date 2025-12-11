package se.digg.eudiw.component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEventLogger {

  Logger logger = LoggerFactory.getLogger(AuthenticationEventLogger.class);

  @EventListener
  public void onSuccess(AuthenticationSuccessEvent success) {
    logger.info("AuthenticationSuccessEvent: {}", success);
  }

  @EventListener
  public void onFailure(AbstractAuthenticationFailureEvent failures) {
    logger.error("AbstractAuthenticationFailureEvent: {}", failures);
  }
}
