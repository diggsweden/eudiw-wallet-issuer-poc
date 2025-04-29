package se.digg.eudiw.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.util.MultiValueMap;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;
import se.digg.eudiw.model.credentialissuer.Grant;
import se.digg.eudiw.util.deserializers.CodeVerifierCustomDeserializer;
import se.digg.eudiw.util.deserializers.GrantCustomDeserializer;
import se.digg.eudiw.util.deserializers.JwkCustomDeserializer;
import se.digg.eudiw.util.deserializers.MultiValueMapCustomDeserializer;

@Configuration
public class ValKeyConfig {

    private final ObjectMapper mapper;

    public ValKeyConfig() {
        mapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Grant.class, new GrantCustomDeserializer());
        module.addDeserializer(CodeVerifier.class, new CodeVerifierCustomDeserializer());
        module.addDeserializer(JWK.class, new JwkCustomDeserializer());
        module.addDeserializer(MultiValueMap.class, new MultiValueMapCustomDeserializer());
        mapper.registerModule(module);
    }

    @Bean
    RedisTemplate<String, MultiValueMap<String, String>> valKeyMultiValueMapTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, MultiValueMap<String, String>> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setValueSerializer(new Jackson2JsonRedisSerializer<>(mapper, MultiValueMap.class));
        return template;
    }

    @Bean
    RedisTemplate<String, CredentialOfferParam> valKeyCredentialOfferParamRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, CredentialOfferParam> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setValueSerializer(new Jackson2JsonRedisSerializer<>(mapper, CredentialOfferParam.class));
        return template;
    }

    @Bean
    RedisTemplate<String, PendingPreAuthorization> pendingPreAuthorizationRedisOperations(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, PendingPreAuthorization> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setValueSerializer(new Jackson2JsonRedisSerializer<>(mapper, PendingPreAuthorization.class));
        return template;
    }

    @Bean
    RedisTemplate<String, JWK> kidJwksOperations(RedisConnectionFactory connectionFactory) {
        // TODO remove with DummyProofService work-around
        RedisTemplate<String, JWK> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        //template.setValueSerializer(new Jackson2JsonRedisSerializer<>(mapper, JWK.class));
        return template;
    }

}


