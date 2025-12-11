package se.digg.eudiw.service;

import com.google.zxing.WriterException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import se.digg.eudiw.model.CredentialOfferDeepLinkAndQrCode;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.List;

public interface CredentialOfferService {
  CredentialOfferParam credentialOffer(String credentialOfferId);

  void store(String credentialOfferId, CredentialOfferParam credentialOffer);

  List<String> selectedCredentials(String selectedCredentialsId);

  void store(String selectedCredentialsId, List<String> selectedCredentials);

  void store(String preAuthCode, PendingPreAuthorization pendingPreAuthorization);

  PendingPreAuthorization pendingPreAuthorization(String preAuthCode);

  // dumb solution in order to support pending issuance operations in the EWC ITB
  String pendingEwcItpIssuance(String credentialOfferId);

  String createCredentialOffer(CodeVerifier pkceVerifier, String codeParam,
      String state, URI callbackUri)
      throws JOSEException, ParseException, IOException, WriterException;

  CredentialOfferDeepLinkAndQrCode credentialOfferDeepLinkAndQrCode(String credentialOfferId)
      throws IOException, WriterException;
}
