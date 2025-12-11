package se.digg.eudiw.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

public class IdProxyAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

  public IdProxyAuthenticationEntryPoint(final String url) {
    super(url);
  }

  @Override
  protected String buildRedirectUrlToLoginPage(final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException authException) {

    return super.buildRedirectUrlToLoginPage(request, response, authException);
  }

}

