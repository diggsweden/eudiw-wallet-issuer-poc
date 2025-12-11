package se.digg.eudiw.service;

import com.nimbusds.jose.jwk.JWK;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DummyProofService {
  // TODO remove this service and lookup from wallet provider
  RedisTemplate<String, JWK> kidJwksOperations;

  public DummyProofService(RedisTemplate<String, JWK> kidJwksOperations) {
    this.kidJwksOperations = kidJwksOperations;
  }

  public void storeJwk(String kid, JWK jwk) {
    kidJwksOperations.opsForValue().set(kid, jwk);
  }

  public Optional<JWK> jwk(String kid) {
    JWK jwk = kidJwksOperations.opsForValue().get(kid);
    if (jwk == null)
      return Optional.empty();
    return Optional.of(jwk);
  }
}
