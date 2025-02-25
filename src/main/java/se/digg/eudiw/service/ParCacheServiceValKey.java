package se.digg.eudiw.service;

import org.checkerframework.checker.units.qual.A;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;

import java.time.Duration;

@Service
@Primary
public class ParCacheServiceValKey implements ParCacheService {

    private final RedisOperations<String, MultiValueMap<String, String>> operations;

    public ParCacheServiceValKey(@Autowired RedisOperations<String, MultiValueMap<String, String>> operations) {
        this.operations = operations;
    }

    @Override
    public void saveParParams(String requestId, MultiValueMap<String, String> storedParams, int ttl) {
        operations.opsForValue().set(requestId, storedParams, Duration.ofMinutes((10)));
    }

    @Override
    public MultiValueMap<String, String> loadParParamsAndRemoveFromCache(String requestId) {
        return operations.opsForValue().get(requestId);
    }
}
