package se.digg.eudiw.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.util.Base64;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class CertificateValidationServiceTest {

  @InjectMocks
  private CertificateValidationService certificateValidationService;

  private KeyPair rootCaKeyPair;
  private X509Certificate rootCaCert;

  private KeyPair intermediateCaKeyPair;
  private X509Certificate intermediateCaCert;

  private KeyPair leafKeyPair;
  private X509Certificate leafCert;

  @BeforeEach
  void setUp() throws Exception {
    // Generate Root CA
    rootCaKeyPair = generateKeyPair();
    rootCaCert =
        createCACertificate(
            "CN=Test Root CA", rootCaKeyPair.getPublic(), rootCaKeyPair.getPrivate(), null);

    // Generate Intermediate CA
    intermediateCaKeyPair = generateKeyPair();
    intermediateCaCert =
        createCACertificate(
            "CN=Test Intermediate CA",
            intermediateCaKeyPair.getPublic(),
            rootCaKeyPair.getPrivate(),
            rootCaCert);

    // Generate Leaf Certificate
    leafKeyPair = generateKeyPair();
    leafCert =
        createLeafCertificate(
            "CN=Test Leaf",
            leafKeyPair.getPublic(),
            intermediateCaKeyPair.getPrivate(),
            intermediateCaCert);

    // Create a KeyStore
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, "password".toCharArray());
    keyStore.setCertificateEntry("test-alias", rootCaCert);

    // Write KeyStore to a byte array
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    keyStore.store(baos, "password".toCharArray());

    // Mock the resource to return the KeyStore
    org.springframework.core.io.Resource resource =
        new org.springframework.core.io.ByteArrayResource(baos.toByteArray());

    ReflectionTestUtils.setField(certificateValidationService, "trustStoreResource", resource);
    ReflectionTestUtils.setField(certificateValidationService, "trustStorePassword", "password");
    ReflectionTestUtils.setField(certificateValidationService, "trustStoreAlias", "test-alias");

    certificateValidationService.init();
  }

  @Test
  void whenChainIsValid_thenValidationSucceeds() throws CertificateEncodingException {
    List<Base64> chain =
        List.of(
            Base64.encode(leafCert.getEncoded()), Base64.encode(intermediateCaCert.getEncoded()));

    assertDoesNotThrow(() -> certificateValidationService.validateCertificateChain(chain));
  }

  @Test
  void whenChainIsEmpty_thenValidationFails() {
    assertThrows(
        SecurityException.class,
        () -> certificateValidationService.validateCertificateChain(List.of()));
  }

  @Test
  void whenChainIsUntrusted_thenValidationFails() throws Exception {
    // Create a new root CA so the chain is not trusted
    KeyPair anotherRootCaKeyPair = generateKeyPair();
    X509Certificate anotherRootCaCert =
        createCACertificate(
            "CN=Another Test Root CA",
            anotherRootCaKeyPair.getPublic(),
            anotherRootCaKeyPair.getPrivate(),
            null);

    KeyPair anotherIntermediateCaKeyPair = generateKeyPair();
    X509Certificate anotherIntermediateCaCert =
        createCACertificate(
            "CN=Another Test Intermediate CA",
            anotherIntermediateCaKeyPair.getPublic(),
            anotherRootCaKeyPair.getPrivate(),
            anotherRootCaCert);

    KeyPair anotherLeafKeyPair = generateKeyPair();
    X509Certificate anotherLeafCert =
        createLeafCertificate(
            "CN=Another Test Leaf",
            anotherLeafKeyPair.getPublic(),
            anotherIntermediateCaKeyPair.getPrivate(),
            anotherIntermediateCaCert);

    List<Base64> chain =
        List.of(
            Base64.encode(anotherLeafCert.getEncoded()),
            Base64.encode(intermediateCaCert.getEncoded()));
    assertThrows(
        SecurityException.class,
        () -> certificateValidationService.validateCertificateChain(chain));
  }

  @Test
  void whenChainHasExpiredCertificate_thenValidationFails() throws Exception {
    X509Certificate expiredLeafCert =
        createExpiredLeafCertificate(
            "CN=Expired Leaf",
            leafKeyPair.getPublic(),
            intermediateCaKeyPair.getPrivate(),
            intermediateCaCert);

    List<Base64> chain =
        List.of(
            Base64.encode(expiredLeafCert.getEncoded()),
            Base64.encode(intermediateCaCert.getEncoded()));

    assertThrows(
        SecurityException.class,
        () -> certificateValidationService.validateCertificateChain(chain));
  }

  @Test
  void whenChainHasNotYetValidCertificate_thenValidationFails() throws Exception {
    X509Certificate notYetValidLeafCert =
        createNotYetValidLeafCertificate(
            "CN=Not Yet Valid Leaf",
            leafKeyPair.getPublic(),
            intermediateCaKeyPair.getPrivate(),
            intermediateCaCert);

    List<Base64> chain =
        List.of(
            Base64.encode(notYetValidLeafCert.getEncoded()),
            Base64.encode(intermediateCaCert.getEncoded()));

    assertThrows(
        SecurityException.class,
        () -> certificateValidationService.validateCertificateChain(chain));
  }

  private KeyPair generateKeyPair() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  private X509Certificate createCACertificate(
      String subjectDN, PublicKey publicKey, PrivateKey signingKey, X509Certificate issuer)
      throws Exception {
    X500Name issuerName =
        (issuer == null)
            ? new X500Name(subjectDN)
            : new X500Name(issuer.getSubjectX500Principal().getName());

    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerName,
            BigInteger.valueOf(System.currentTimeMillis()),
            Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
            Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
            new X500Name(subjectDN),
            publicKey);

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signingKey);
    return new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));
  }

  private X509Certificate createLeafCertificate(
      String subjectDN, PublicKey publicKey, PrivateKey signingKey, X509Certificate issuer)
      throws Exception {
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuer.getSubjectX500Principal().getName()),
            BigInteger.valueOf(System.currentTimeMillis()),
            Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
            Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
            new X500Name(subjectDN),
            publicKey);

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signingKey);
    return new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));
  }

  private X509Certificate createExpiredLeafCertificate(
      String subjectDN, PublicKey publicKey, PrivateKey signingKey, X509Certificate issuer)
      throws Exception {
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuer.getSubjectX500Principal().getName()),
            BigInteger.valueOf(System.currentTimeMillis()),
            Date.from(Instant.now().minus(2, ChronoUnit.DAYS)),
            Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
            new X500Name(subjectDN),
            publicKey);

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signingKey);
    return new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));
  }

  private X509Certificate createNotYetValidLeafCertificate(
      String subjectDN, PublicKey publicKey, PrivateKey signingKey, X509Certificate issuer)
      throws Exception {
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuer.getSubjectX500Principal().getName()),
            BigInteger.valueOf(System.currentTimeMillis()),
            Date.from(Instant.now().plus(1, ChronoUnit.DAYS)),
            Date.from(Instant.now().plus(2, ChronoUnit.DAYS)),
            new X500Name(subjectDN),
            publicKey);

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signingKey);
    return new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));
  }
}
