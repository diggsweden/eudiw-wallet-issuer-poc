package se.digg.eudiw.authorization;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import java.util.function.Consumer;

public class CustomRedirectUriValidator
    implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

  private static final Logger logger = LoggerFactory.getLogger(CustomRedirectUriValidator.class);

  @Override
  public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
    OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
        authenticationContext.getAuthentication();
    String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

    logger.info("Skip Redirect URI verification for {}", requestedRedirectUri);
  }
}
