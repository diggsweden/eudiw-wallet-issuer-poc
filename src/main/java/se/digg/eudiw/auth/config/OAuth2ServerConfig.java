package se.digg.eudiw.auth.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;

import se.digg.eudiw.auth.context.EudiwSessionSecurityContextRepository;
import se.digg.eudiw.auth.model.SwedenConnectPrincipal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.nimbusds.jose.jwk.source.JWKSource;

@Configuration
@EnableWebSecurity
public class OAuth2ServerConfig {

  @Autowired
  private SwedenConnectAuthenticationProvider authProvider;

  @Autowired
  private EudiwSessionSecurityContextRepository contextRepository;

  @Autowired
  private EudiwConfig config;

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.exceptionHandling(exceptions -> exceptions.
         authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login")));
    
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
                
    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
      http
        .authorizeHttpRequests(
          authorizeRequests ->
            authorizeRequests
              .requestMatchers("/cert/**").permitAll()
                    .requestMatchers("/auth/login").permitAll()
                    .requestMatchers("/auth/return").permitAll()
              .requestMatchers("/actuator/**").permitAll()
              .requestMatchers("/error**").permitAll()
                    .requestMatchers("/oauth2/authorize").permitAll()
                    .requestMatchers("/oauth2/**").permitAll()
                    .requestMatchers("/auth2/token").permitAll()
                    .requestMatchers("/login/oauth2/**").permitAll()
                    .requestMatchers("/.well-known/**").permitAll()
                    .requestMatchers("/login").permitAll()
                    .requestMatchers("/").permitAll()
                    .requestMatchers("/favicon.ico").permitAll()

                    .requestMatchers("/callback").permitAll()
                    .requestMatchers("/auth-flow").permitAll()
                    .requestMatchers("/init-auth-flow").permitAll()
                    .requestMatchers("/demo").permitAll()

                    .requestMatchers("/v3/api-docs/**").permitAll()
                    .requestMatchers("/actuator/**").permitAll()
                    .requestMatchers("/demo-credential").permitAll()
                    .requestMatchers("/demo-oidfed-client").permitAll()
                    .requestMatchers("/wallet-cert.pem").permitAll()
                    .requestMatchers("/credential").hasAuthority("SCOPE_VerifiablePortableDocumentA1")
                    .requestMatchers("/credential_offer").hasAuthority("SCOPE_VerifiablePortableDocumentA1")


                    .anyRequest().authenticated()
          );
      http.csrf(AbstractHttpConfigurer::disable);
      http.cors(cors -> cors.disable());
      http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
      http.securityContext(securityContext -> securityContext.
        securityContextRepository(contextRepository)
      );
      
      SwedenconnectAuthenticationReturnFilter authFilter = new SwedenconnectAuthenticationReturnFilter(authenticationManager, contextRepository);
      http.addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class);

      http.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));

      return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
      AuthenticationManagerBuilder authenticationManagerBuilder = 
          http.getSharedObject(AuthenticationManagerBuilder.class);
      authenticationManagerBuilder.authenticationProvider(authProvider);
      return authenticationManagerBuilder.build();
  }

  @Bean
  @Order(3)
  public RegisteredClientRepository registeredClientRepository() {



    RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId(config.getClientId())
      .clientAuthenticationMethods(s -> {
        s.add(ClientAuthenticationMethod.NONE);
      })
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);


    registeredClientBuilder = registeredClientBuilder.redirectUri(String.format("%s/login/oauth2/code/messaging-client-pkce", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/callback", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/auth-flow", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/callback-demo-auth", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/credentials", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/callback-demo-pre-auth", config.getIssuerBaseUrl()))
      .redirectUri("com.example.eudiwdemo:/oauthredirect")
      .redirectUri(config.getIssuerBaseUrl());

    for (String uri : config.getRedirectUris()) {
      registeredClientBuilder = registeredClientBuilder.redirectUri(uri);
    }

    registeredClientBuilder = registeredClientBuilder.scope("identitycredential.read")
      .scope("VerifiablePortableDocumentA1")
      .scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
      .clientSettings(ClientSettings.builder()
                      .requireAuthorizationConsent(true)
                      .requireProofKey(true) //Only PKCE is supported
                      .build())
      .tokenSettings(TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Generate JWT token
                    .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                    .accessTokenTimeToLive(Duration.ofSeconds(30 * 60))
                    .refreshTokenTimeToLive(Duration.ofSeconds(60 * 60))
                    .reuseRefreshTokens(true)
                    .build());
    RegisteredClient registeredClient = registeredClientBuilder.build();
    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
      return AuthorizationServerSettings.builder().issuer(config.getIssuer()).build();
    }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = Jwks.generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> accessTokenCustomizer() {
      return (context) -> {
        Authentication principal = context.getPrincipal();
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
          Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
              .collect(Collectors.toSet());
          
          context.getClaims().claim("authorities", authorities);  

          // TODO det mesta borde flyttas till idToken eller userinfo någonting
          JwtClaimsSet.Builder claims = context.getClaims();
          if (principal.getPrincipal() instanceof SwedenConnectPrincipal) {
            SwedenConnectPrincipal p = (SwedenConnectPrincipal) principal.getPrincipal();
            if (p.getSubjAttributes().getPersonalNumber() != null) claims.claim("personalNumber", p.getSubjAttributes().getPersonalNumber());
            if (p.getSubjAttributes().getName() != null) claims.claim("name", p.getSubjAttributes().getName());
            if (p.getSubjAttributes().getGivenName() != null) claims.claim("givenName", p.getSubjAttributes().getGivenName());
            if (p.getSubjAttributes().getSurname() != null) claims.claim("surname", p.getSubjAttributes().getSurname());
            if (p.getSubjAttributes().getCoordinationNumber() != null) claims.claim("coordinationNumber", p.getSubjAttributes().getCoordinationNumber());
            if (p.getSubjAttributes().getPrid() != null) claims.claim("prid", p.getSubjAttributes().getPrid());
            if (p.getSubjAttributes().getPridPersistence() != null) claims.claim("pridPersistence", p.getSubjAttributes().getPridPersistence());
            if (p.getSubjAttributes().getEidasPersonIdentifier() != null) claims.claim("eidasPersonIdentifier", p.getSubjAttributes().getEidasPersonIdentifier());
            if (p.getSubjAttributes().getPersonalNumberBinding() != null) claims.claim("personalNumberBinding", p.getSubjAttributes().getPersonalNumberBinding());
            if (p.getSubjAttributes().getOrgNumber() != null) claims.claim("orgNumber", p.getSubjAttributes().getOrgNumber());
            if (p.getSubjAttributes().getOrgAffiliation() != null) claims.claim("orgAffiliation", p.getSubjAttributes().getOrgAffiliation());
            if (p.getSubjAttributes().getOrgName() != null) claims.claim("orgName", p.getSubjAttributes().getOrgName());
            if (p.getSubjAttributes().getOrgUnit() != null) claims.claim("orgUnit", p.getSubjAttributes().getOrgUnit());
            if (p.getSubjAttributes().getUserCertificate() != null) claims.claim("userCertificate", p.getSubjAttributes().getUserCertificate());
            if (p.getSubjAttributes().getUserSignature() != null) claims.claim("userSignature", p.getSubjAttributes().getUserSignature());
            if (p.getSubjAttributes().getDeviceIp() != null) claims.claim("deviceIp", p.getSubjAttributes().getDeviceIp());
            if (p.getSubjAttributes().getAuthnEvidence() != null) claims.claim("authnEvidence", p.getSubjAttributes().getAuthnEvidence());
            if (p.getSubjAttributes().getCountry() != null) claims.claim("country", p.getSubjAttributes().getCountry());
            if (p.getSubjAttributes().getBirthName() != null) claims.claim("birthName", p.getSubjAttributes().getBirthName());
            if (p.getSubjAttributes().getPlaceOfbirth() != null) claims.claim("placeOfbirth", p.getSubjAttributes().getPlaceOfbirth());
            if (p.getSubjAttributes().getAge() != null) claims.claim("age", p.getSubjAttributes().getAge());
            if (p.getSubjAttributes().getBirthDate() != null) claims.claim("birthDate", p.getSubjAttributes().getBirthDate());
          }
          
        }
      };
  }


  static class Jwks {

    private Jwks() {
    }

    public static RSAKey generateRsa() {
      KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
      RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
      RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
      return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
    }
  }

  static class KeyGeneratorUtils {

    private KeyGeneratorUtils() {
    }

    static KeyPair generateRsaKey() {
      KeyPair keyPair;
      try {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
      } catch (Exception ex) {
        throw new IllegalStateException(ex);
      }
      return keyPair;
    }
  } 
}
