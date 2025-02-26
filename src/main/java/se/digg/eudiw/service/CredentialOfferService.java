package se.digg.eudiw.service;

import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;

public interface CredentialOfferService {
    CredentialOfferParam credentialOffer(String credentialOfferId);
    void store(String credentialOfferId, CredentialOfferParam credentialOffer);

}
