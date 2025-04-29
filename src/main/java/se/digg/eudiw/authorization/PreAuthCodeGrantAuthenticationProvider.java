package se.digg.eudiw.authorization;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public class PreAuthCodeGrantAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final RegisteredClientRepository registeredClientRepository;
    Logger logger = LoggerFactory.getLogger(PreAuthCodeGrantAuthenticationProvider.class);

    public PreAuthCodeGrantAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                  OAuth2TokenGenerator<?> tokenGenerator,
                                                  RegisteredClientRepository registeredClientRepository) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof PreAuthCodeGrantAuthenticationToken preAuthCodeGrantAuthenticationToken)) return null;

        // Ensure the client is authenticated
        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(preAuthCodeGrantAuthenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // Ensure the client is configured to use this authorization grant type
        assert registeredClient != null;
        if (registeredClient.getAuthorizationGrantTypes().stream().noneMatch(grant -> PreAuthParameterNames.PRE_AUTHORIZED_CODE_GRANT.equals(grant.getValue()))) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .principal(authentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(preAuthCodeGrantAuthenticationToken.getGrantType())
                .authorizationGrant(preAuthCodeGrantAuthenticationToken)
                .build();

                logger.info("preAuthCodeGrantAuthenticationToken: {}", preAuthCodeGrantAuthenticationToken);

                OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
                if (generatedAccessToken == null) {
                    OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                            "The token generator failed to generate the access token.", null);
                    throw new OAuth2AuthenticationException(error);
                }
                OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                        generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                        generatedAccessToken.getExpiresAt(), null);

                // Initialize the OAuth2Authorization
                OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                        .principalName(clientPrincipal.getName())
                        .authorizationGrantType(preAuthCodeGrantAuthenticationToken.getGrantType());
                if (generatedAccessToken instanceof ClaimAccessor) {
                    authorizationBuilder.token(accessToken, (metadata) ->
                            metadata.put(
                                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                    ((ClaimAccessor) generatedAccessToken).getClaims())
                    );
                } else {
                    authorizationBuilder.accessToken(accessToken);
                }
                OAuth2Authorization authorization = authorizationBuilder.build();

                // Save the OAuth2Authorization
                this.authorizationService.save(authorization);

                return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PreAuthCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(PreAuthCodeGrantAuthenticationToken authentication) {
        String clientId = authentication.getClientId();
        if (clientId == null) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(authentication.getClientId());
        if (registeredClient == null) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);

        return new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.NONE, null);
        /*OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (authentication != null && PreAuthCodeGrantAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);

         */
    }

}
