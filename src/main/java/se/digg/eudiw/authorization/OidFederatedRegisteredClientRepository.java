package se.digg.eudiw.authorization;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.Assert;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.service.OpenIdFederationService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OidFederatedRegisteredClientRepository implements RegisteredClientRepository {

    private final EudiwConfig config;
    private final OpenIdFederationService openIdFederationService;
    private final Map<String, RegisteredClient> idRegistrationMap;
    private final Map<String, RegisteredClient> clientIdRegistrationMap;

    public OidFederatedRegisteredClientRepository(EudiwConfig config, OpenIdFederationService openIdFederationService ) {
        this.config = config;
        this.openIdFederationService = openIdFederationService;
        ConcurrentHashMap<String, RegisteredClient> idRegistrationMapResult = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
        this.idRegistrationMap = idRegistrationMapResult;
        this.clientIdRegistrationMap = clientIdRegistrationMapResult;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        // no need to save - the client registration is done in federation
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return (RegisteredClient)this.idRegistrationMap.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        RegisteredClient client = (RegisteredClient)this.clientIdRegistrationMap.get(clientId);
        if (client == null) {
            return buildRegisteredClient(clientId);
        }
        return client;
    }


    private RegisteredClient buildRegisteredClient(String clientId) {

        //WalletOAuthClientMetadata metadata = openIdFederationService.resolveWallet(clientId);

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        byte[] shasum = digest.digest(clientId.getBytes(StandardCharsets.UTF_8));
        String id = new String(shasum, StandardCharsets.UTF_8);

        RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(id)
                .clientId(clientId)
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
                .redirectUri(String.format("%s/pre-auth-credential-offer", config.getIssuerBaseUrl()))
                .redirectUri(config.getIssuerBaseUrl());

        for (String uri : config.getRedirectUris()) {
            registeredClientBuilder = registeredClientBuilder.redirectUri(uri);
        }

        registeredClientBuilder = registeredClientBuilder
                .scope("eu.europa.ec.eudi.pid.1")
                .scope(OidcScopes.OPENID)
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


        RegisteredClient client = registeredClientBuilder.build();


        return client;
    }
}
