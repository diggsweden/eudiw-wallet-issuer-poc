package se.digg.eudiw.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.stereotype.Service;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;

import java.util.concurrent.TimeUnit;

@Service
public class CredentialOfferServiceImpl implements CredentialOfferService {

    private final RedisOperations<String, CredentialOfferParam> operations;
    private final RedisOperations<String, PendingPreAuthorization> pendingPreAuthorizationRedisOperations;
    private final EudiwConfig eudiwConfig;

    public CredentialOfferServiceImpl(@Autowired RedisOperations<String, CredentialOfferParam> operations, @Autowired RedisOperations<String, PendingPreAuthorization> pendingPreAuthorizationRedisOperations, @Autowired EudiwConfig eudiwConfig) {
        this.operations = operations;
        this.eudiwConfig = eudiwConfig;
        this.pendingPreAuthorizationRedisOperations = pendingPreAuthorizationRedisOperations;
    }

    @Override
    public CredentialOfferParam credentialOffer(String credentialOfferId) {
        // TODO: change back to getAndDelete - temporary fix for android reference implementation wallet app
        return operations.opsForValue().get(credentialOfferId);
    }

    @Override
    public void store(String credentialOfferId, CredentialOfferParam credentialOffer) {
        operations.opsForValue().set(credentialOfferId, credentialOffer, eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public void store(String preAuthCode, PendingPreAuthorization pendingPreAuthorization) {
        pendingPreAuthorizationRedisOperations.opsForValue().set(preAuthCode, pendingPreAuthorization, eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public PendingPreAuthorization pendingPreAuthorization(String preAuthCode) {
        return pendingPreAuthorizationRedisOperations.opsForValue().getAndDelete(preAuthCode);
    }
}
