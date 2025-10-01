// src/main/java/se/digg/eudiw/service/CertificateValidationService.java

package se.digg.eudiw.service;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

@Service
public class CertificateValidationService {

  private static final Logger logger = LoggerFactory.getLogger(CertificateValidationService.class);

  // Update @Value annotations to match the new YAML structure
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
      // Use the KeyStore class for .p12 files
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(is, trustStorePassword.toCharArray());

      // Get the certificate from the keystore using its alias
      Certificate cert = keyStore.getCertificate(trustStoreAlias);
      if (cert == null) {
        throw new RuntimeException(
            "Certificate with alias '" + trustStoreAlias + "' not found in keystore.");
      }
      if (!(cert instanceof X509Certificate rootCaCert)) {
        throw new RuntimeException(
            "Certificate with alias '" + trustStoreAlias + "' is not an X.509 certificate.");
      }

        // Create a TrustAnchor for the Root CA
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
   * Validates a certificate chain against the configured Root CA. (This method does not need any
   * changes)
   *
   * @param x5cChain A list of Base64-encoded DER X.509 certificates. The first cert is the leaf.
   * @throws SecurityException if the chain is invalid or not trusted.
   */
  public void validateCertificateChain(List<String> x5cChain) throws SecurityException {
    if (x5cChain == null || x5cChain.isEmpty()) {
      throw new SecurityException("Certificate chain is missing in JWT 'x5c' header.");
    }

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      List<Certificate> certChain = new ArrayList<>();
      for (String encodedCert : x5cChain) {
        byte[] decodedCert = Base64.getDecoder().decode(encodedCert);
        certChain.add(cf.generateCertificate(new java.io.ByteArrayInputStream(decodedCert)));
      }

      CertPath certPath = cf.generateCertPath(certChain);
      PKIXParameters params = new PKIXParameters(this.trustAnchors);
      params.setRevocationEnabled(false); // Keep revocation disabled for this example

      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      validator.validate(certPath, params);

      logger.info("Successfully validated certificate chain against the trusted Root CA.");

    } catch (CertPathValidatorException e) {
      logger.warn(
          "Certificate path validation failed: {} on certificate {}",
          e.getMessage(),
          e.getCertPath() != null ? e.getCertPath().getCertificates().get(e.getIndex()) : "Unknown certificate");
      throw new SecurityException("Certificate path validation failed: " + e.getMessage(), e);
    } catch (Exception e) {
      logger.error("An unexpected error occurred during certificate validation.", e);
      throw new SecurityException("Could not validate certificate chain due to an error.", e);
    }
  }
}
