package se.digg.eudiw.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import se.digg.eudiw.authentication.IdProxyRequestBuilder;
import se.digg.eudiw.authentication.SwedenConnectAuthenticationProvider;
import se.digg.eudiw.authentication.SwedenconnectAuthenticationReturnFilter;
import se.digg.eudiw.authorization.CustomRedirectUriValidator;
import se.digg.eudiw.authorization.EudiwJwtGenerator;
import se.digg.eudiw.authorization.OAuth2ParAuthorizationCodeRequestAuthenticationConverter;
import se.digg.eudiw.authorization.OidFederatedRegisteredClientRepository;
import se.digg.eudiw.authorization.PreAuthCodeGrantAuthenticationConverter;
import se.digg.eudiw.authorization.PreAuthCodeGrantAuthenticationProvider;
import se.digg.eudiw.service.ParCacheService;
import se.digg.eudiw.service.CredentialOfferService;
import se.digg.eudiw.service.DummyProofService;
import se.digg.eudiw.service.OpenIdFederationService;
import se.digg.eudiw.service.OidcUserInfoService;

import se.digg.eudiw.context.EudiwSessionSecurityContextRepository;

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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.source.JWKSource;

@Configuration
@EnableWebSecurity
public class OAuth2ServerConfig {

  @Autowired
  private SwedenConnectAuthenticationProvider authProvider;

  @Autowired
  EudiwSessionSecurityContextRepository contextRepository;

  @Autowired
  OidcUserInfoService oidcUserInfoService;

  @Autowired
  private EudiwConfig config;

  @Autowired
  ApplicationContext applicationContext;

  @Bean
  @Order(1)
  public SecurityFilterChain parFilterChain(HttpSecurity http) throws Exception {
    http
            .securityMatcher("/oauth2/par")
            .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                    .requestMatchers(HttpMethod.POST, "/oauth2/par").permitAll()
            )
            .csrf(AbstractHttpConfigurer::disable);
    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, @Autowired RegisteredClientRepository registeredClientRepository, @Autowired AuthenticationManager authenticationManager, @Autowired OAuth2AuthorizationService authorizationService, @Autowired OAuth2TokenGenerator<?> tokenGenerator, @Autowired ParCacheService parCacheService, @Autowired CredentialOfferService credentialOfferService, DummyProofService dummyProofService) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
            OAuth2AuthorizationServerConfigurer.authorizationServer();

    Consumer<OAuth2AuthorizationServerMetadata.Builder>
        authorizationServerMetadataCustomizer = new Consumer<OAuth2AuthorizationServerMetadata.Builder>() {
      @Override
      public void accept(OAuth2AuthorizationServerMetadata.Builder builder) {
        builder.claim("pushed_authorization_request_endpoint", String.format("%s/oauth2/par", config.getIssuerBaseUrl()));
        builder.claim("require_pushed_authorization_requests", true);
      }
    };


    http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .authorizeHttpRequests( authorizeHttpRequests -> authorizeHttpRequests
                    .requestMatchers("/oauth2/token*").permitAll()
                    //.requestMatchers("/oauth2/authorize*").permitAll()
                    .anyRequest().authenticated()
            )
            .with(authorizationServerConfigurer, (authorizationServer) ->
                    authorizationServer
                            .registeredClientRepository(registeredClientRepository)
                            .tokenGenerator(tokenGenerator(oidcUserInfoService))
                            .oidc(oidc -> oidc
                                    .providerConfigurationEndpoint(providerConfigurationEndpoint ->
                                            providerConfigurationEndpoint.providerConfigurationCustomizer(builder -> builder
                                                    .claim("pushed_authorization_request_endpoint", String.format("%s/%s", config.getIssuerBaseUrl(), "oauth2/par")))


                                    )
                            )	// Enable OpenID Connect 1.0
                            .authorizationEndpoint(authorizationEndpoint ->
                                    authorizationEndpoint
                                            .authorizationRequestConverter(new OAuth2ParAuthorizationCodeRequestAuthenticationConverter(parCacheService))
                                            .authenticationProvider(authProvider)
                                            .authenticationProviders(configureAuthenticationValidator())
                                            //.authorizationRequestConverters(converters -> converters.addFirst(new ParAuthenticationConverter(parCacheService)))
                                            .errorResponseHandler((req, res, error) -> {
                                              res.getWriter().write("FOOBAR!");
                                              res.setStatus(HttpStatus.OK.value()); 
                                            })
                            )
                            .tokenEndpoint(tokenEndpoint -> tokenEndpoint

                                    .accessTokenRequestConverter(new PreAuthCodeGrantAuthenticationConverter(credentialOfferService, dummyProofService))
                                    .authenticationProvider(new PreAuthCodeGrantAuthenticationProvider(authorizationService, tokenGenerator, registeredClientRepository)))
                            .authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint ->
                                authorizationServerMetadataEndpoint
                                    .authorizationServerMetadataCustomizer(authorizationServerMetadataCustomizer)
                            )

            )
            .csrf(AbstractHttpConfigurer::disable)
            .exceptionHandling(exception -> exception
                    // Redirect to the login page when not authenticated
                    // authorization endpoint
                    .authenticationEntryPoint( new LoginUrlAuthenticationEntryPoint("/auth/login"))
            );

    return http.build();
  }

  @Bean
  @Order(3)
  SecurityFilterChain authenticationSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

    http
            .securityMatcher("/auth/*")
            .authenticationProvider(authProvider)
            .authorizeHttpRequests(
                    authorizeRequests ->
                            authorizeRequests
                                    .requestMatchers("/auth/login").permitAll()
                                    .requestMatchers("/auth/return/*").permitAll()
            )
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            ;

    return http.build();
  }

  @Bean
  @Order(4)
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

      http
            .addFilterBefore(new SwedenconnectAuthenticationReturnFilter(authenticationManager, contextRepository), UsernamePasswordAuthenticationFilter.class)
            .authenticationProvider(authProvider)
            .authorizeHttpRequests(
                    authorizeRequests ->
                            authorizeRequests
                                    .requestMatchers("/favicon.ico").permitAll()
                                    .requestMatchers("/.well-known/**").permitAll()
                                    .requestMatchers("/").permitAll()
                                    .requestMatchers("/index.html").permitAll()
                                    .requestMatchers("/images/**").permitAll()
                                    .requestMatchers("/style/**").permitAll()
                                    .requestMatchers("/cert/**").permitAll()
                                    .requestMatchers("/actuator/**").permitAll()
                                    .requestMatchers("/v3/api-docs/**").permitAll()
                                    .requestMatchers("/swagger-ui.html").permitAll()
                                    .requestMatchers("/swagger-ui/**").permitAll()
                                    .requestMatchers("/error**").permitAll()
                                    .requestMatchers("/login*").permitAll()
                                    .requestMatchers("/demo-credential").permitAll()
                                    .requestMatchers("/app").permitAll()
                                    .requestMatchers("/prepare-credential-offer").permitAll()
                                    .requestMatchers("/credential-offer").permitAll()
                                    .requestMatchers("/credential_offer/**").permitAll()
                                    .requestMatchers("/credentialIssuanceRequest").permitAll()
                                    .requestMatchers("/issueStatus").permitAll()
                                    .requestMatchers("/qr").permitAll()
                                    .requestMatchers("/qr-sdjwt").permitAll()
                                    .requestMatchers("/qr-mdoc").permitAll()
                                    .requestMatchers("/pre-auth-credential_offer").authenticated() //hasAuthority("SCOPE_VerifiablePortableDocumentA1")
                                    .requestMatchers("/demo-oidfed-client").authenticated()
                                    .requestMatchers("/credential").authenticated() //hasAuthority("SCOPE_VerifiablePortableDocumentA1")
                                    .anyRequest().authenticated()
            )
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
            .exceptionHandling(exception -> exception
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
            );

      http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .securityContext(securityContext -> securityContext.securityContextRepository(contextRepository));
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
  public IdProxyRequestBuilder idProxyRequestBuilder() {
    return new IdProxyRequestBuilder(config);
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository(OpenIdFederationService openIdFederationService) {

    return new OidFederatedRegisteredClientRepository(config/*, openIdFederationService */);
/*
    RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId(config.getClientId())
      .clientAuthenticationMethods(s -> {
        s.add(ClientAuthenticationMethod.NONE);
      })
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code"));


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
                    .build())
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build());
    RegisteredClient registeredClient = registeredClientBuilder.build();
    return new InMemoryRegisteredClientRepository(registeredClient);

 */
  }

  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
      return AuthorizationServerSettings.builder().issuer(config.getIssuer()).build();
  }

  @Bean
  public OAuth2AuthorizationService authorizationService() {
    return new InMemoryOAuth2AuthorizationService();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = Jwks.generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
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

  @Bean
  public OAuth2TokenGenerator<?> tokenGenerator(OidcUserInfoService oidcUserInfoService) {
    JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
    EudiwJwtGenerator jwtGenerator = new EudiwJwtGenerator(jwtEncoder);
    jwtGenerator.setJwtCustomizer(tokenCustomizer(oidcUserInfoService));
    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
    return new DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
          OidcUserInfoService userInfoService) {
    return (context) -> {
      if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
        OidcUserInfo userInfo = userInfoService.loadUser(
                context.getPrincipal().getName());
        context.getClaims().claims(claims ->
                claims.putAll(userInfo.getClaims()));
      }
    };
  }

  @Bean
  public AuthenticationEventPublisher authenticationEventPublisher
          (ApplicationEventPublisher applicationEventPublisher) {
    return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
  }


  private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
    return (authenticationProviders) ->
            authenticationProviders.forEach((authenticationProvider) -> {
              if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {
                Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
                        // Override default redirect_uri validator
                        new CustomRedirectUriValidator()
                                // Reuse default scope validator
                                .andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR);

                ((OAuth2AuthorizationCodeRequestAuthenticationProvider) authenticationProvider)
                        .setAuthenticationValidator(authenticationValidator);
              }
            });
  }

}
