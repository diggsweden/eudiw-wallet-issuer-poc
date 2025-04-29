package se.digg.eudiw.config;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import lombok.Getter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import se.oidc.oidfed.base.security.JWTSigningCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

import java.security.Security;
import java.util.Set;

@Component
public class SignerConfig {

    Logger logger = LoggerFactory.getLogger(SignerConfig.class);

    private final JWSSigner jwsSigner;

    @Getter
    private final ECDSAVerifier jwsVerifier;
    @Getter
    private final JWTSigningCredential jwtSigningCredential;

    private final JWK jwk;

    public SignerConfig(@Autowired CredentialBundles credentialBundles) {
        try {
            // Load BouncyCastle as JCA provider
            Security.addProvider(new BouncyCastleProvider());

            final PkiCredential issuerCredential = credentialBundles.getCredential("issuercredential");

            jwk = new JwkTransformerFunction().apply(issuerCredential);

            jwsSigner = new ECDSASigner(issuerCredential.getPrivateKey(), Curve.P_256);
            jwsVerifier = new ECDSAVerifier(jwk.toPublicJWK().toECKey().toECPublicKey(), Set.of(Curve.P_256.getName()));

            jwtSigningCredential = JWTSigningCredential.builder().signer(jwsSigner).verifier(jwsVerifier).supportedAlgorithms(jwsSigner.supportedJWSAlgorithms().stream().toList()).build();

        } catch (Exception e) {
            logger.error("Could not initialize signer configuration", e);
            throw new RuntimeException(e);
        }
    }

    public JWK getPublicJwk() {
        return jwk.toPublicJWK();
    }

    public JWSSigner getSigner() {
        return jwsSigner;
    }

}
