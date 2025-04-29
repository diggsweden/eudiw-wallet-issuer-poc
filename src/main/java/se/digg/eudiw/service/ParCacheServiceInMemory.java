package se.digg.eudiw.service;

import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

/**
 * TODO: replace with valkey for multipod support and built in ttl on request-uris
 */
@Service
public class ParCacheServiceInMemory implements ParCacheService {

    Map<String, MultiValueMap<String, String>> savedParams = new HashMap<>();

    public ParCacheServiceInMemory() {
    }

    @Override
    public void saveParParams(String requestId, MultiValueMap<String, String> storedParams, int ttl) {
        savedParams.put(requestId, storedParams);
    }

    @Override
    public MultiValueMap<String, String> loadParParamsAndRemoveFromCache(String requestId) {
        return savedParams.get(requestId);
    }
}
