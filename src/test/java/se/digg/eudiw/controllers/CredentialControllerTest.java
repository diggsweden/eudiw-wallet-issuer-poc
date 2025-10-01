package se.digg.eudiw.controllers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import se.digg.eudiw.model.credentialissuer.CredentialFormatEnum;
import se.digg.eudiw.model.credentialissuer.CredentialParam;
import se.digg.eudiw.model.credentialissuer.JwtProof;
import se.digg.eudiw.service.CertificateValidationService; // Import the service

@SpringBootTest
@AutoConfigureMockMvc
class CredentialControllerTest {

  @Autowired private MockMvc mockMvc;

  @Autowired private ObjectMapper objectMapper;

  @MockitoBean private CertificateValidationService certificateValidationService;

  private JwtRequestPostProcessor userJwt;
  private CredentialParam requestBody;

  // Test data that will represent a "valid" key and certificate
  private ECKey validWalletKey;
  private List<Base64> validX5cChain;
  private List<String> validX5cChainAsStrings;

  @BeforeEach
  void setup() throws Exception {
    final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_jwt_vc_json";

    // 2. Generate a key and a self-signed certificate for it
    validWalletKey = new ECKeyGenerator(Curve.P_256).generate();
    X509Certificate cert = generateSelfSignedCertificate(validWalletKey.toKeyPair());
    validX5cChain = Collections.singletonList(Base64.encode(cert.getEncoded()));
    validX5cChainAsStrings =
        validX5cChain.stream().map(Base64::toString).collect(Collectors.toList());

    // 3. Configure the mock to accept our "valid" certificate chain
    // When the service is called with this specific chain, it will do nothing (succeed).
    doNothing().when(certificateValidationService).validateCertificateChain(validX5cChainAsStrings);

    // Build the request body with a valid proof JWT containing the x5c header
    JwtProof jwtProof = new JwtProof();
    jwtProof.setProofType("jwt");
    jwtProof.setJwt(createProofJwt(validWalletKey, validX5cChain));

    requestBody = new CredentialParam();
    requestBody.setFormat(CredentialFormatEnum.VC_SD_JWT);
    requestBody.setProof(jwtProof);
    requestBody.setCredentialConfigurationId(CREDENTIAL_CONFIG_ID);

    userJwt =
        SecurityMockMvcRequestPostProcessors.jwt()
            .jwt(builder -> builder.claim("givenName", "john").claim("surname", "smith").build());
  }

  @Test
  void credential_issuesCredentialSuccessfully() throws Exception {
    // This test now works because the setup configures a valid proof JWT
    // and the mocked service is told to accept its certificate chain.
    mockMvc
        .perform(
            post("/credential")
                .with(userJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.credential").exists());
  }

  @Test
  void credential_whenProofSignatureIsInvalid_returns400() throws Exception {
    // We still use a valid x5c header, but sign the JWT with a different key
    // to test the signature validation logic specifically.
    ECKey mismatchedSigningKey =
        new ECKeyGenerator(Curve.P_256).generate(); // This key will sign the JWT

    JWSHeader proofHeader =
        new JWSHeader.Builder(JWSAlgorithm.ES256)
            .jwk(validWalletKey.toPublicJWK()) // Header key is correct
            .x509CertChain(validX5cChain) // Cert chain is correct
            .build();

    SignedJWT proofJwt = new SignedJWT(proofHeader, createClaims());
    proofJwt.sign(new ECDSASigner(mismatchedSigningKey)); // Signature created with wrong key!
    String invalidProofJwtString = proofJwt.serialize();

    requestBody.getProof().setJwt(invalidProofJwtString);

    mockMvc
        .perform(
            post("/credential")
                .with(userJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("invalid_proof"));
  }

  // 4. Add a new test for invalid certificate chain
  @Test
  void credential_whenCertChainIsInvalid_returns401() throws Exception {

    // Configure the mock to THROW an exception when it sees this untrusted chain
    doThrow(new SecurityException("Untrusted certificate!"))
        .when(certificateValidationService)
        .validateCertificateChain(any());

    mockMvc
        .perform(
            post("/credential")
                .with(userJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isUnauthorized()) // Expect 401 Unauthorized
        .andExpect(
            content()
                .string(
                    "An error occurred: 401 UNAUTHORIZED \"JWT is not signed by a trusted issuer\""));
  }

  private JWTClaimsSet createClaims() {
    return new JWTClaimsSet.Builder()
        .audience("https://issuer.example.com")
        .claim("nonce", UUID.randomUUID().toString())
        .issueTime(new Date())
        .build();
  }

  private String createProofJwt(ECKey signingKey, List<Base64> x5cChain) throws Exception {
    JWSHeader proofHeader =
        new JWSHeader.Builder(JWSAlgorithm.ES256)
            .jwk(signingKey.toPublicJWK())
            .x509CertChain(x5cChain) // Include the certificate chain
            .build();

    SignedJWT proofJwt = new SignedJWT(proofHeader, createClaims());
    proofJwt.sign(new ECDSASigner(signingKey));
    return proofJwt.serialize();
  }

  /** Generates a self-signed X.509 certificate using Bouncy Castle. */
  private X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
    X500Name issuer = new X500Name("CN=Test Wallet, O=Test, C=SE");
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    Instant now = Instant.now();
    Date notBefore = Date.from(now);
    Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

    JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());

    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");

    return new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certBuilder.build(contentSignerBuilder.build(keyPair.getPrivate())));
  }
}
