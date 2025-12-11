package se.digg.eudiw.controllers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

import java.util.Optional;
import java.util.UUID;

import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import se.digg.eudiw.model.credentialissuer.CredentialFormatEnum;
import se.digg.eudiw.model.credentialissuer.CredentialParam;
import se.digg.eudiw.model.credentialissuer.JwtProof;
import se.digg.eudiw.service.CertificateValidationService;
import se.digg.eudiw.service.DummyProofService;

@Disabled("The test requires wallet-provider to run on localhost to work")
@SpringBootTest
@AutoConfigureMockMvc
class WuaToCredentialControllerTest {

  private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_jwt_vc_json";
  @Autowired
  private MockMvc mockMvc;
  @Autowired
  private ObjectMapper objectMapper;
  @MockitoBean
  private DummyProofService dummyProofService;
  @Autowired
  private CertificateValidationService certificateValidationService;
  private JwtRequestPostProcessor mockUserJwt;
  private CredentialParam requestBody;

  @BeforeEach
  void setup() throws Exception {
    ECKey jwk = new ECKeyGenerator(Curve.P_256).generate();
    Mockito.when(dummyProofService.jwk("wallet-provider")).thenReturn(Optional.of(jwk));

    mockUserJwt =
        SecurityMockMvcRequestPostProcessors.jwt()
            .jwt(builder -> builder.claim("givenName", "john").claim("surname", "smith").build());

    String jwkJson = jwk.toPublicJWK().toJSONString();
    String jsonString = objectMapper.writeValueAsString(jwkJson);

    String walletProviderBody =
        "{\"walletId\":\"" + UUID.randomUUID() + "\",\"jwk\":" + jsonString + "}";

    WebClient walletProviderWebClient =
        WebClient.builder().baseUrl("http://localhost:8080").build();
    String wua =
        walletProviderWebClient
            .post()
            .uri("/wallet-unit-attestation")
            .contentType(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(walletProviderBody))
            .retrieve()
            .bodyToMono(String.class)
            .block();

    JwtProof jwtProof = new JwtProof();
    jwtProof.setProofType("jwt");
    String proofCompactString = createProof(jwk, wua);
    jwtProof.setJwt(proofCompactString);

    requestBody = new CredentialParam();
    requestBody.setFormat(CredentialFormatEnum.VC_SD_JWT);
    requestBody.setProof(jwtProof);
    requestBody.setCredentialConfigurationId(CREDENTIAL_CONFIG_ID);
  }

  @Test
  void wuaToCredential_issuesCredentialSuccessfully() throws Exception {
    mockMvc
        .perform(
            post("/credential")
                .with(mockUserJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.credential").exists());
  }

  private String createProof(ECKey jwk, String keyAttestation) throws JOSEException {
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(new JOSEObjectType("openid4vci-proof+jwt"))
        .customParam("key_attestation", keyAttestation)
        .build();

    JWTClaimsSet claims = new JWTClaimsSet.Builder().build();

    SignedJWT jwt = new SignedJWT(header, claims);

    jwt.sign(new ECDSASigner(jwk));

    return jwt.serialize();
  }
}
