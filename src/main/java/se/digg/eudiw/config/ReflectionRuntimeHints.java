package se.digg.eudiw.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;

import se.swedenconnect.auth.commons.dto.ClientAuthRequest;

public class ReflectionRuntimeHints implements RuntimeHintsRegistrar {
  @Override
  public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
    hints.reflection().registerType(ClientAuthRequest.class, MemberCategory.values());
  }
}
