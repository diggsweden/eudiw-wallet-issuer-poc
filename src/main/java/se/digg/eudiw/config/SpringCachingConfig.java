package se.digg.eudiw.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.cache.Cache;
import org.springframework.cache.annotation.CachingConfigurer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.google.common.cache.CacheBuilder;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class SpringCachingConfig implements CachingConfigurer {

  Logger logger = LoggerFactory.getLogger(SpringCachingConfig.class);

  @Autowired
  EudiwConfig eudiwConfig;

  @Bean
  public CacheManager cacheManager() {
    ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager("trust-mark") {

      @Override
      protected Cache createConcurrentMapCache(final String name) {
        Integer ttl = eudiwConfig.getOpenidFederation().trustListTtlInSeconds();
        logger.info("cache config trustListTtlInSeconds: {}", ttl);
        return new ConcurrentMapCache(
            name,
            CacheBuilder.newBuilder()
                .expireAfterWrite(ttl, TimeUnit.SECONDS)
                .maximumSize(100)
                .build()
                .asMap(),
            false);
      }
    };

    return cacheManager;
  }
}
