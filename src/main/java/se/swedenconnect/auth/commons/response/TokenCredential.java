package se.swedenconnect.auth.commons.response;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Token verification credential data
 */
public record TokenCredential(
    X509Certificate certificate,
    byte[] sha256Hash,
    String kid) {

  /**
   * Create ID token verification credential based on a certificate with no kid
   *
   * @param certificate trusted certificate
   */
  public TokenCredential(X509Certificate certificate) {
    this(certificate, getThumbprint(certificate), null);
  }

  /**
   * Create ID token verification credential based on a certificate with kid
   *
   * @param certificate trusted certificate
   * @param kid key identifier
   */
  public TokenCredential(X509Certificate certificate, String kid) {
    this(certificate, getThumbprint(certificate), kid);
  }

  private static byte[] getThumbprint(X509Certificate certificate) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      return md.digest(certificate.getEncoded());
    } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
