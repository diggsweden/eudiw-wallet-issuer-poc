package se.digg.eudiw.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

public final class JwtUtils {
  public static SignedJWT getKeyAttestation(JWSHeader header)
      throws ParseException {
    Object keyAttestation = header.getCustomParam("key_attestation");
    if (!(keyAttestation instanceof String compactStringJwt) || compactStringJwt.isEmpty()) {
      throw new ParseException("key_attestation missing or not a string", 0);
    }
    return SignedJWT.parse(compactStringJwt);
  }

  public static Optional<JWK> firstAttestedKey(SignedJWT keyAttestation, ObjectMapper mapper) {
    List<Object> attestedKeys;
    try {
      JWTClaimsSet claims = keyAttestation.getJWTClaimsSet();
      attestedKeys = claims.getListClaim("attested_keys");
    } catch (ParseException e) {
      return Optional.empty();
    }

    if (attestedKeys == null || attestedKeys.isEmpty()) {
      return Optional.empty();
    }

    try {
      Object firstKey = attestedKeys.getFirst();
      String json = mapper.writeValueAsString(firstKey);
      JWK jwk = JWK.parse(json);
      return Optional.of(jwk);
    } catch (ParseException | JsonProcessingException e) {
      return Optional.empty();
    }
  }
}
