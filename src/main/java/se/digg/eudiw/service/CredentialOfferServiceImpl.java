package se.digg.eudiw.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.stereotype.Service;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;

import java.util.concurrent.TimeUnit;

@Service
public class CredentialOfferServiceImpl implements CredentialOfferService {

    private final RedisOperations<String, CredentialOfferParam> operations;
    private final EudiwConfig eudiwConfig;

    public CredentialOfferServiceImpl(@Autowired RedisOperations<String, CredentialOfferParam> operations, @Autowired EudiwConfig eudiwConfig) {
        this.operations = operations;
        this.eudiwConfig = eudiwConfig;
    }

    @Override
    public CredentialOfferParam credentialOffer(String credentialOfferId) {
        return operations.opsForValue().getAndDelete(credentialOfferId);
    }

    @Override
    public void store(String credentialOfferId, CredentialOfferParam credentialOffer) {
        operations.opsForValue().set(credentialOfferId, credentialOffer, eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    }
}
