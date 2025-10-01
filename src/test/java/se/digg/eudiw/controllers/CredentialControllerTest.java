package se.digg.eudiw.controllers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;
import se.digg.eudiw.model.credentialissuer.CredentialFormatEnum;
import se.digg.eudiw.model.credentialissuer.CredentialParam;
import se.digg.eudiw.model.credentialissuer.JwtProof;

@SpringBootTest
@AutoConfigureMockMvc
class CredentialControllerTest {

  @Autowired private MockMvc mockMvc;

  @Autowired private ObjectMapper objectMapper;

  @Test
  void credential_happyCase_issuesCredentialSuccessfully() throws Exception {
    final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_jwt_vc_json";

    ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
    JWSHeader proofHeader =
        new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(walletKey.toPublicJWK()).build();
    JWTClaimsSet proofClaims =
        new JWTClaimsSet.Builder()
            .audience("https://issuer.example.com")
            .claim("nonce", UUID.randomUUID().toString())
            .issueTime(new Date())
            .build();
    SignedJWT proofJwt = new SignedJWT(proofHeader, proofClaims);
    proofJwt.sign(new ECDSASigner(walletKey));
    String proofJwtString = proofJwt.serialize();

    JwtProof jwtProof = new JwtProof();
    jwtProof.setProofType("jwt");
    jwtProof.setJwt(proofJwtString);

    CredentialParam requestBody = new CredentialParam();
    requestBody.setFormat(CredentialFormatEnum.VC_SD_JWT);
    requestBody.setProof(jwtProof);
    requestBody.setCredentialConfigurationId(CREDENTIAL_CONFIG_ID);

    JwtRequestPostProcessor userJwt =
        SecurityMockMvcRequestPostProcessors.jwt()
            .jwt(builder -> builder.claim("givenName", "john").claim("surname", "smith").build());

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
  void credential_sadCase_throwsTokenIssuingException() throws Exception {
    final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_jwt_vc_json";

    ECKey signingKey = new ECKeyGenerator(Curve.P_256).generate(); // This key will sign the JWT
    ECKey headerKey =
        new ECKeyGenerator(Curve.P_256).generate(); // This key's public part will go in the header

    JWSHeader proofHeader =
        new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(headerKey.toPublicJWK()).build();

    JWTClaimsSet proofClaims =
        new JWTClaimsSet.Builder()
            .audience("https://issuer.example.com")
            .claim("nonce", UUID.randomUUID().toString())
            .issueTime(new Date())
            .build();

    SignedJWT proofJwt = new SignedJWT(proofHeader, proofClaims);
    proofJwt.sign(new ECDSASigner(signingKey)); // Signature is created with a different key!
    String invalidProofJwtString = proofJwt.serialize();

    // --- CONSTRUCT THE REQUEST ---
    JwtProof jwtProof = new JwtProof();
    jwtProof.setProofType("jwt");
    jwtProof.setJwt(invalidProofJwtString);

    CredentialParam requestBody = new CredentialParam();
    requestBody.setFormat(CredentialFormatEnum.VC_SD_JWT);
    requestBody.setProof(jwtProof);
    requestBody.setCredentialConfigurationId(CREDENTIAL_CONFIG_ID);

    JwtRequestPostProcessor userJwt =
        SecurityMockMvcRequestPostProcessors.jwt()
            .jwt(builder -> builder.claim("givenName", "john").claim("surname", "smith").build());

    // --- ACT & ASSERT ---
    mockMvc
        .perform(
            post("/credential")
                .with(userJwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
        .andExpect(status().isBadRequest()) // HTTP 400
        .andExpect(jsonPath("$.error").value("invalid_proof"))
        .andExpect(jsonPath("$.c_nonce").exists())
        .andExpect(jsonPath("$.credential").doesNotExist());
  }
}
