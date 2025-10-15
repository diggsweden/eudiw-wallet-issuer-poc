package se.digg.eudiw.controllers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
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
import se.digg.eudiw.service.CertificateValidationService;

@SpringBootTest
@AutoConfigureMockMvc
class CredentialControllerTest {

  private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_jwt_vc_json";
  private static final List<Base64> mockX5cChain = Collections.emptyList();

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;
  @MockitoBean private CertificateValidationService certificateValidationService;

  private JwtRequestPostProcessor mockUserJwt;
  private CredentialParam requestBody;
  private ECKey validWalletKey;
  private String keyAttestation;

  @BeforeEach
  void setup() throws Exception {
    mockUserJwt =
        SecurityMockMvcRequestPostProcessors.jwt()
            .jwt(builder -> builder.claim("givenName", "john").claim("surname", "smith").build());

    doNothing().when(certificateValidationService).validateCertificateChain(mockX5cChain);

    validWalletKey = new ECKeyGenerator(Curve.P_256).generate();
    ECKey walletProviderKey = new ECKeyGenerator(Curve.P_256).generate();
    keyAttestation = createKeyAttestation(validWalletKey, walletProviderKey);

    JwtProof jwtProof = new JwtProof();
    jwtProof.setProofType("jwt");
    jwtProof.setJwt(createProofJwt(validWalletKey, keyAttestation));

    requestBody = new CredentialParam();
    requestBody.setFormat(CredentialFormatEnum.VC_SD_JWT);
    requestBody.setProof(jwtProof);
    requestBody.setCredentialConfigurationId(CREDENTIAL_CONFIG_ID);
  }

  @Test
  void credential_issuesCredentialSuccessfully() throws Exception {
    mockMvc
        .perform(
            post("/credential")
                .with(mockUserJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.credential").exists());
  }

  @Test
  void credential_whenProofSignatureIsInvalid_returns400() throws Exception {
    ECKey wrongSigningKey = new ECKeyGenerator(Curve.P_256).generate();

    JWSHeader proofHeader =
        new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(new JOSEObjectType("openid4vci-proof+jwt"))
            .customParam("key_attestation", keyAttestation)
            .build();

    SignedJWT proofJwt = new SignedJWT(proofHeader, createClaims());
    proofJwt.sign(new ECDSASigner(wrongSigningKey));
    String invalidProofJwtString = proofJwt.serialize();

    requestBody.getProof().setJwt(invalidProofJwtString);

    mockMvc
        .perform(
            post("/credential")
                .with(mockUserJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("invalid_proof"));
  }

  @Test
  void credential_whenCertChainIsInvalid_returns401() throws Exception {
    doThrow(new SecurityException("Untrusted certificate!"))
        .when(certificateValidationService)
        .validateCertificateChain(any());

    mockMvc
        .perform(
            post("/credential")
                .with(mockUserJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isUnauthorized())
        .andExpect(
            content()
                .string(
                    "An error occurred: 401 UNAUTHORIZED \"JWT is not signed by a trusted party\""));
  }

  private JWTClaimsSet createClaims() {
    return new JWTClaimsSet.Builder()
        .audience("https://issuer.example.com")
        .claim("nonce", UUID.randomUUID().toString())
        .issueTime(new Date())
        .build();
  }

  private String createProofJwt(ECKey signingKey, String keyAttestation) throws Exception {
    JWSHeader proofHeader =
        new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(new JOSEObjectType("openid4vci-proof+jwt"))
            .customParam("key_attestation", keyAttestation)
            .jwk(signingKey.toPublicJWK())
            .build();

    SignedJWT proofJwt = new SignedJWT(proofHeader, createClaims());
    proofJwt.sign(new ECDSASigner(signingKey));
    return proofJwt.serialize();
  }

  private String createKeyAttestation(ECKey walletKey, ECKey walletProviderKey) throws JOSEException {
    List<Object> attestedKeys = List.of(walletKey.toPublicJWK().toJSONObject());

    JWSHeader proofHeader =
        new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(new JOSEObjectType("keyattestation+jwt"))
            .x509CertChain(mockX5cChain)
            .build();


    JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .audience("https://issuer.example.com")
            .claim("nonce", UUID.randomUUID().toString())
            .claim("attested_keys", attestedKeys)
            .issueTime(new Date())
            .build();

    SignedJWT proofJwt = new SignedJWT(proofHeader, claims);
    proofJwt.sign(new ECDSASigner(walletProviderKey));

    return proofJwt.serialize();
  }
}
