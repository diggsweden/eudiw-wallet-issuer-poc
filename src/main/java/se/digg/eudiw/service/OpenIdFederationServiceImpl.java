package se.digg.eudiw.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import se.digg.eudiw.ApiClient;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.client.DefaultApi;
import se.oidc.oidfed.md.wallet.credentialissuer.WalletOAuthClientMetadata;
import se.swedenconnect.auth.commons.response.IdTokenValidationException;
import se.swedenconnect.auth.commons.response.TokenCredential;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Service
public class OpenIdFederationServiceImpl implements OpenIdFederationService {

    Logger logger = LoggerFactory.getLogger(OpenIdFederationServiceImpl.class);

    private final EudiwConfig eudiwConfig;

    private final RestTemplate restTemplate;

    private final DefaultApi oidFederation;

    private final List<TokenCredential> trustedCredentials;

    private final String walletUriTemplate;

    public OpenIdFederationServiceImpl(@Autowired EudiwConfig eudiwConfig, @Autowired RestTemplate restTemplate, @Autowired List<TokenCredential> tokenCredentials) {
        this.eudiwConfig = eudiwConfig;
        this.restTemplate = restTemplate;

        ApiClient client = new ApiClient(restTemplate);
        client.setBasePath(eudiwConfig.getOpenidFederation().baseUrl());
        oidFederation = new DefaultApi(client);

        trustedCredentials = tokenCredentials;

        walletUriTemplate = String.format("%s%%s", eudiwConfig.getOpenidFederation().walletBaseUri());
    }

    @Override
    public WalletOAuthClientMetadata resolveWallet(String walletId) {
        WalletOAuthClientMetadata clientMetadata = null;
        String oidFedJwt = oidFederation.nameResolveGet(
                "wallet-provider",
                String.format(walletUriTemplate, walletId),
                eudiwConfig.getOpenidFederation().walletProviderAnchor(),
                null);
        try {
            SignedJWT signedJwt = parseJwt(oidFedJwt);
            //signedJwt.getJWTClaimsSet().getClaims().entrySet().stream().forEach(claimEntry -> System.out.println("ITEM" + claimEntry.getKey() + "|" + claimEntry.getValue()));
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> metadataClaim = (Map<String, Object>) signedJwt.getJWTClaimsSet().getClaim("metadata");
            String metadataClaimJson = objectMapper.writeValueAsString(metadataClaim.get("oauth_client"));
            clientMetadata = objectMapper.readValue(metadataClaimJson, WalletOAuthClientMetadata.class);
        }
        catch (IdTokenValidationException e) {
           // throw new RuntimeException(e);
            logger.error("Id token validation error", e);
        } catch (ParseException e) {
           // throw new RuntimeException(e);
            logger.error("Parse error", e);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return clientMetadata;
    }

    @Override
    @Cacheable("trust-mark")
    public String trustMark(String trustMarkId, String subject) {
        logger.info("loading to trust list cache");
        return oidFederation.nameTrustMarkGet("trust-mark-issuer",trustMarkId, subject);
    }

    @Override
    public List<String> activeWallets() {
        return oidFederation.nameSubordinateListingGet("wallet-provider", null, true, eudiwConfig.getOpenidFederation().walletProviderAnchor(), false);
    }

    @CacheEvict(value = "trust-mark", allEntries = true)
    @Scheduled(fixedRateString = "${caching.spring.trust-mark-ttl}")
    public void emptyTrustListCache() {
        logger.info("emptying trust list cache");
    }

    public SignedJWT parseJwt(String oidFedJwt) throws IdTokenValidationException {
        SignedJWT signedJWT = null;
        try {
            signedJWT = SignedJWT.parse(oidFedJwt);
            JWSVerifier verifier = getVerifier(signedJWT);
            boolean valid = signedJWT.verify(verifier);
            if (!valid) {
                throw new IdTokenValidationException("ID token signature validation failed", signedJWT);
            }
            //Object metadata = signedJWT.getJWTClaimsSet().getClaim("metadata");
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

    private JWSVerifier getVerifier(SignedJWT signedJWT)
            throws IdTokenValidationException, CertificateEncodingException, NoSuchAlgorithmException, JOSEException {

        JWSHeader header = signedJWT.getHeader();

        if (trustedCredentials == null || trustedCredentials.isEmpty()) {
            throw new IdTokenValidationException("No trusted credentials available", signedJWT);
        }

        X509Certificate trustedCertificate = getTrustedCertificate(header);
        if (trustedCertificate == null) {
            throw new IdTokenValidationException(
                    "Non of the trusted certificates matches the Id token JWT header declarations", signedJWT);
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
