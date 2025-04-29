package se.digg.eudiw.service;

import com.nimbusds.jose.jwk.JWK;
import org.springframework.security.oauth2.jwt.Jwt;
import se.digg.eudiw.model.credentialissuer.CredentialFormatEnum;
import se.digg.wallet.datatypes.common.TokenIssuingException;

public interface CredentialIssuerService {
    String credential(CredentialFormatEnum reqFormat, String credentialType, JWK deviceProofPublicKey, Jwt jwt) throws TokenIssuingException;
}
