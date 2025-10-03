package se.digg.eudiw.service;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.X509CertChainUtils;
import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.*;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

@Service
public class CertificateValidationService {

  private static final Logger logger = LoggerFactory.getLogger(CertificateValidationService.class);

  @Value("${eudiw.trust-store.location}")
  private Resource trustStoreResource;

  @Value("${eudiw.trust-store.password}")
  private String trustStorePassword;

  @Value("${eudiw.trust-store.alias}")
  private String trustStoreAlias;

  private Set<TrustAnchor> trustAnchors;

  /** Loads the trusted Root CA certificate from the configured PKCS#12 keystore. */
  @PostConstruct
  public void init() {
    try (InputStream is = trustStoreResource.getInputStream()) {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(is, trustStorePassword.toCharArray());

      Certificate cert = keyStore.getCertificate(trustStoreAlias);
      if (cert == null) {
        throw new RuntimeException(
            "Certificate with alias '" + trustStoreAlias + "' not found in keystore.");
      }
      if (!(cert instanceof X509Certificate rootCaCert)) {
        throw new RuntimeException(
            "Certificate with alias '" + trustStoreAlias + "' is not an X.509 certificate.");
      }

      TrustAnchor trustAnchor = new TrustAnchor(rootCaCert, null);
      this.trustAnchors = Collections.singleton(trustAnchor);

      logger.info(
          "Successfully loaded Root CA for trust validation: {}",
          rootCaCert.getSubjectX500Principal());

    } catch (Exception e) {
      logger.error(
          "Failed to load the Root CA certificate from keystore. Certificate chain validation will fail.",
          e);
      throw new RuntimeException("Could not initialize Trust Store from .p12 file", e);
    }
  }

  /**
   * Validates a certificate chain against the configured Root CA.
   *
   * @param x5cChain A list of Base64-encoded DER X.509 certificates. The first cert is the leaf.
   * @throws SecurityException if the chain is invalid or not trusted.
   */
  public void validateCertificateChain(List<Base64> x5cChain) throws SecurityException {
    if (x5cChain == null || x5cChain.isEmpty()) {
      throw new SecurityException("Certificate chain is missing in JWT 'x5c' header.");
    }

    try {
      List<X509Certificate> certChain = X509CertChainUtils.parse(x5cChain);
      if (certChain.isEmpty()) {
        throw new SecurityException("The 'x5c' header parameter contained no certificates.");
      }

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      CertPath certPath = cf.generateCertPath(certChain);
      PKIXParameters params = new PKIXParameters(this.trustAnchors);
      params.setRevocationEnabled(false);

      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      validator.validate(certPath, params);

      logger.info("Successfully validated certificate chain against the trusted Root CA.");

    } catch (ParseException e) {
      logger.warn("Failed to parse certificate chain from 'x5c' header: {}", e.getMessage());
      throw new SecurityException("Failed to parse certificate chain: " + e.getMessage(), e);
    } catch (CertPathValidatorException e) {
      logger.warn(
          "Certificate path validation failed: {} on certificate {}",
          e.getMessage(),
          e.getCertPath() != null
              ? ((X509Certificate) e.getCertPath().getCertificates().get(e.getIndex()))
                  .getSubjectX500Principal()
              : "Unknown certificate");
      throw new SecurityException("Certificate path validation failed: " + e.getMessage(), e);
    } catch (Exception e) {
      logger.error("An unexpected error occurred during certificate validation.", e);
      throw new SecurityException("Could not validate certificate chain due to an error.", e);
    }
  }
}
