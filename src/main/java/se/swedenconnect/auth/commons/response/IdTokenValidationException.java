package se.swedenconnect.auth.commons.response;

import java.io.Serial;

import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;

/**
 * Exception when validating an ID token
 */
public class IdTokenValidationException extends Exception {

  @Getter
  private final SignedJWT signedJWT;

  @Serial
  private static final long serialVersionUID = -6908586099690472926L;

  /** {@inheritDoc} */
  public IdTokenValidationException(String message, SignedJWT signedJWT) {
    super(message);
    this.signedJWT = signedJWT;
  }

  /** {@inheritDoc} */
  public IdTokenValidationException(String message, Throwable cause, SignedJWT signedJWT) {
    super(message, cause);
    this.signedJWT = signedJWT;
  }

}
