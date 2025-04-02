package se.digg.eudiw.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import se.oidc.oidfed.md.wallet.credentialissuer.CredentialIssuerMetadata;

import java.security.cert.CertificateEncodingException;

public interface MetadataService {
    CredentialIssuerMetadata metadata() throws CertificateEncodingException, JOSEException, JsonProcessingException;
}
