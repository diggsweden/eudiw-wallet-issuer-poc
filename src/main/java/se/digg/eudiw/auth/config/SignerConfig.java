package se.digg.eudiw.auth.config;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import lombok.Getter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import se.oidc.oidfed.base.security.JWTSigningCredential;
import java.nio.file.Files;

import java.nio.file.Paths;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Component
public class SignerConfig {

    Logger logger = LoggerFactory.getLogger(SignerConfig.class);

    private final JWSSigner jwsSigner;

    @Getter
    private final ECDSAVerifier jwsVerifier;
    @Getter
    private final JWTSigningCredential jwtSigningCredential;

    private final JWK jwk;

    public SignerConfig(@Autowired EudiwConfig eudiwConfig) {
        try {
            // Load BouncyCastle as JCA provider
            Security.addProvider(new BouncyCastleProvider());

            // Parse the EC key file
            String pemKey = new String(Files.readAllBytes(Paths.get(eudiwConfig.getIssuerSignerKeyPemFile())));
            jwk = JWK.parseFromPEMEncodedObjects(pemKey);

            ECPrivateKey privateKey = jwk.toECKey().toECPrivateKey();
            ECPublicKey publicKey = jwk.toECKey().toECPublicKey();

            jwsSigner = new ECDSASigner(privateKey);
            jwsVerifier = new ECDSAVerifier(publicKey);

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
