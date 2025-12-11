package se.swedenconnect.auth.commons.response;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.auth.commons.idtoken.CustomClaim;
import se.swedenconnect.auth.commons.idtoken.IdTokenClaims;
import se.swedenconnect.auth.commons.idtoken.SourceID;
import se.swedenconnect.auth.commons.idtoken.SubjAttributeType;
import se.swedenconnect.auth.commons.idtoken.SubjAttributes;

/**
 * Description
 */
@Slf4j
public class IdTokenValidator {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final List<TokenCredential> trustedCredentials;

  public IdTokenValidator(List<TokenCredential> trustedCredentials) {
    this.trustedCredentials = trustedCredentials;
  }

  public SignedJWT validateIdToken(String idToken) throws IdTokenValidationException {
    SignedJWT signedJWT = null;
    // TODO config id proxy public key for validation
    try {
      signedJWT = SignedJWT.parse(idToken);
      JWSVerifier verifier = getVerifier(signedJWT);
      boolean valid = signedJWT.verify(verifier);
      if (!valid) {
        throw new IdTokenValidationException("ID token signature validation failed", signedJWT);
      }
    } catch (ParseException e) {
      throw new IdTokenValidationException("Unable to parse ID token", e, signedJWT);
    } catch (JOSEException e) {
      throw new IdTokenValidationException("Signature validation error", e, signedJWT);
    } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
      throw new IdTokenValidationException("Invalid trust configuration", e, signedJWT);
    } catch (RuntimeException e) {
      throw new IdTokenValidationException("Invalid token data", e, signedJWT);
    }
    return signedJWT;
  }

  public IdTokenClaims getIdTokenClaims(SignedJWT signedJWT)
      throws ParseException, IdTokenValidationException, JsonProcessingException {

    IdTokenClaims.IdTokenClaimsBuilder builder = IdTokenClaims.builder();
    JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

    SourceID sourceID = null;
    Object sourceClaimObject = jwtClaimsSet.getClaim("source");
    if (sourceClaimObject != null) {
      sourceID = OBJECT_MAPPER.readValue(OBJECT_MAPPER.writeValueAsString(sourceClaimObject),
          SourceID.class);
    }

    builder
        .tokenId(jwtClaimsSet.getJWTID())
        .issuer(jwtClaimsSet.getIssuer())
        .issueTime(jwtClaimsSet.getIssueTime().toInstant())
        .expirationTime(jwtClaimsSet.getExpirationTime().toInstant())
        .audience(jwtClaimsSet.getAudience() == null || jwtClaimsSet.getAudience().isEmpty()
            ? null
            : jwtClaimsSet.getAudience().get(0))
        .idp((String) jwtClaimsSet.getClaim(CustomClaim.idp.name()))
        .inResponseTo((String) jwtClaimsSet.getClaim(CustomClaim.irt.name()))
        .loa((String) jwtClaimsSet.getClaim(CustomClaim.loa.name()))
        .sourceId(sourceID);

    try {
      Map<String, Object> subjectClaimsMap = (Map<String, Object>) jwtClaimsSet
          .getClaim(CustomClaim.subjectAttr.name());
      String subjClaimsJson = OBJECT_MAPPER.writeValueAsString(subjectClaimsMap);
      SubjAttributes subjAttributes = OBJECT_MAPPER.readValue(subjClaimsJson, SubjAttributes.class);
      builder.subjectAttributes(subjAttributes);
      Set<String> claimNameSet = subjectClaimsMap.keySet();
      Map<SubjAttributeType, Object> subjectClaimsEnumMap = new HashMap<>();
      for (String claimName : claimNameSet) {
        try {
          SubjAttributeType type = SubjAttributeType.valueOf(claimName);
          subjectClaimsEnumMap.put(type, subjectClaimsMap.get(claimName));
        } catch (IllegalArgumentException e) {
          log.debug("Unsupported attribute type {}", claimName);
        }
      }
      builder.subjectAttributeMap(subjectClaimsEnumMap);
    } catch (Exception ex) {
      throw new IdTokenValidationException("Invalid subject claims", signedJWT);
    }
    return builder.build();
  }

  private JWSVerifier getVerifier(SignedJWT signedJWT)
      throws IdTokenValidationException, CertificateEncodingException, NoSuchAlgorithmException,
      JOSEException {

    JWSHeader header = signedJWT.getHeader();

    if (trustedCredentials == null || trustedCredentials.isEmpty()) {
      throw new IdTokenValidationException("No trusted credentials available", signedJWT);
    }

    X509Certificate trustedCertificate = getTrustedCertificate(header);
    if (trustedCertificate == null) {
      throw new IdTokenValidationException(
          "Non of the trusted certificates matches the Id token JWT header declarations",
          signedJWT);
    }

    PublicKey publicKey = trustedCertificate.getPublicKey();
    if (publicKey instanceof ECPublicKey) {
      return new ECDSAVerifier((ECPublicKey) publicKey);
    }
    return new RSASSAVerifier((RSAPublicKey) publicKey);
  }

  private X509Certificate getTrustedCertificate(JWSHeader header)
      throws CertificateEncodingException, NoSuchAlgorithmException {

    String keyID = header.getKeyID();
    Base64URL x509CertSHA256Thumbprint = header.getX509CertSHA256Thumbprint();
    List<Base64> x509CertChain = header.getX509CertChain();

    for (TokenCredential tokenCredential : trustedCredentials) {
      if (x509CertChain != null && !x509CertChain.isEmpty()) {
        // we have a cert in the header. Select if matching
        Base64 trustedCertB64 = Base64.encode(tokenCredential.certificate().getEncoded());
        if (trustedCertB64.equals(x509CertChain.get(0))) {
          // Match. Return matched cert
          return tokenCredential.certificate();
        }
      }
      if (x509CertSHA256Thumbprint != null) {
        // We have a thumbprint in the header. Select if matching
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        Base64URL x5t256 = Base64URL.encode(md.digest(tokenCredential.certificate().getEncoded()));
        if (x5t256.equals(x509CertSHA256Thumbprint)) {
          // Match. Return matched cert
          return tokenCredential.certificate();
        }
      }
      if (keyID != null && keyID.equals(tokenCredential.kid())) {
        return tokenCredential.certificate();
      }
    }
    // We found no match. Return null.
    return null;
  }

}
