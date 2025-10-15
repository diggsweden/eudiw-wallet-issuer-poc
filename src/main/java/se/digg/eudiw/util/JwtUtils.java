package se.digg.eudiw.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.List;

public final class JwtUtils {
    public static SignedJWT getKeyAttestation(JWSHeader header)
            throws ParseException, IllegalArgumentException {
        Object keyAttestation = header.getCustomParam("key_attestation");
        if (!(keyAttestation instanceof String compactStringJwt) || compactStringJwt.isEmpty()) {
            throw new IllegalArgumentException(
                    "key_attestation missing or not a string");
        }
        return SignedJWT.parse(compactStringJwt);
    }

    public static JWK firstAttestedKey(SignedJWT keyAttestation, ObjectMapper mapper)
            throws ParseException, IllegalArgumentException, JsonProcessingException {
        JWTClaimsSet claims = keyAttestation.getJWTClaimsSet();
        List<Object> keys = claims.getListClaim("attested_keys");
        if (keys == null || keys.isEmpty() ) {
            throw new IllegalArgumentException(
                    "attested_keys missing or empty");
        }

        Object firstKey = keys.getFirst();
        String json = mapper.writeValueAsString(firstKey);
        return JWK.parse(json);
    }
}