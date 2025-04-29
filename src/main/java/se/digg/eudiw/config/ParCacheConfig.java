package se.digg.eudiw.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.util.MultiValueMap;
import se.digg.eudiw.service.ParCacheService;
import se.digg.eudiw.service.ParCacheServiceValKey;

@Configuration
public class ParCacheConfig {

    private final RedisOperations<String, MultiValueMap<String, String>> operations;

    ParCacheConfig(@Autowired RedisOperations<String, MultiValueMap<String, String>> operations) {
        this.operations = operations;
    }

    ParCacheService parCacheService() {
        return new ParCacheServiceValKey(operations);
    }
}
