package se.digg.eudiw.config;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import lombok.Data;
import se.swedenconnect.auth.commons.response.IdTokenValidator;
import se.swedenconnect.auth.commons.response.TokenCredential;


@ConfigurationProperties(prefix = "eudiw")
@Configuration
@Data
public class SecurityConfig {

  public static final CertificateFactory certificateFactory;

  List<TrustedCert> tokenIssuerCert;


  static {
    try {
      certificateFactory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  @Data
  public static class TrustedCert {
    private Resource certLocation;
    private String kid;
  }

  @Bean
  List<TokenCredential> tokenCredentials(SecurityConfig trustConfig)
      throws IOException, CertificateException {
    List<TokenCredential> tokenCredentialList = new ArrayList<>();
    List<SecurityConfig.TrustedCert> certList = trustConfig.getTokenIssuerCert();
    if (certList != null) {
      for (SecurityConfig.TrustedCert cert : certList) {
        X509Certificate x5c = (X509Certificate) certificateFactory
            .generateCertificate(cert.getCertLocation().getInputStream());
        tokenCredentialList.add(new TokenCredential(x5c, cert.getKid()));
      }
    }
    return tokenCredentialList;
  }

  @Bean
  IdTokenValidator idTokenValidator(SecurityConfig trustConfig)
      throws IOException, CertificateException {
    List<TokenCredential> tokenCredentialList = new ArrayList<>();
    List<SecurityConfig.TrustedCert> certList = trustConfig.getTokenIssuerCert();
    if (certList != null) {
      for (SecurityConfig.TrustedCert cert : certList) {
        X509Certificate x5c = (X509Certificate) certificateFactory
            .generateCertificate(cert.getCertLocation().getInputStream());
        tokenCredentialList.add(new TokenCredential(x5c, cert.getKid()));
      }
    }
    return new IdTokenValidator(tokenCredentialList);
  }


  // @Bean
  // public SecurityFilterChain defaultSecurityFilter(HttpSecurity http) throws Exception {
  // http
  // .authorizeHttpRequests((authorize) -> authorize
  // .requestMatchers("/v3/api-docs/**").permitAll()
  // .requestMatchers("/actuator/**").permitAll()
  // .requestMatchers("/.well-known/**").permitAll()
  // .requestMatchers("/demo-credential").permitAll()
  // .requestMatchers("/wallet-cert.pem").permitAll()
  // .requestMatchers("/credential").hasAuthority("SCOPE_identitycredential.read")
  // .requestMatchers("/credential_offer").hasAuthority("SCOPE_identitycredential.read")
  // .requestMatchers("/issuer/credential").hasAuthority("SCOPE_identitycredential.read")
  // .requestMatchers("/issuer/credential_offer").hasAuthority("SCOPE_identitycredential.read")
  // .anyRequest().denyAll()
  // )
  // .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
  //
  // return http.build();
  // }

}
