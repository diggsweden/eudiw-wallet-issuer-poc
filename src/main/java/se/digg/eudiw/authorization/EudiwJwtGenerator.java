package se.digg.eudiw.authorization;

import org.springframework.lang.Nullable;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import se.digg.eudiw.authentication.SwedenConnectPrincipal;

// TODO vi borde kunna konfigurera endast en jwtCustomizer men av någon anledning har det krånglat...

public final class EudiwJwtGenerator implements OAuth2TokenGenerator<Jwt> {
    private final JwtEncoder jwtEncoder;
    private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    public EudiwJwtGenerator(JwtEncoder jwtEncoder) {
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.jwtEncoder = jwtEncoder;
    }

    @Nullable
    public Jwt generate(OAuth2TokenContext context) {
        if (context.getTokenType() != null && (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) || "id_token".equals(context.getTokenType().getValue()))) {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) && !OAuth2TokenFormat.SELF_CONTAINED.equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
                return null;
            } else {
                String issuer = null;
                if (context.getAuthorizationServerContext() != null) {
                    issuer = context.getAuthorizationServerContext().getIssuer();
                }

                RegisteredClient registeredClient = context.getRegisteredClient();
                Instant issuedAt = Instant.now();
                JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;
                Instant expiresAt;
                if ("id_token".equals(context.getTokenType().getValue())) {
                    expiresAt = issuedAt.plus(30L, ChronoUnit.MINUTES);
                    if (registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm() != null) {
                        jwsAlgorithm = registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm();
                    }
                } else {
                    expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());
                }

                JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
                if (StringUtils.hasText(issuer)) {
                    claimsBuilder.issuer(issuer);
                }

                // after id proxy login is the
                if (context.getPrincipal().getPrincipal() instanceof SwedenConnectPrincipal) {
                    SwedenConnectPrincipal swedenConnectPrincipal = (SwedenConnectPrincipal)context.getPrincipal().getPrincipal();
                    claimsBuilder.claim("personalNumber", swedenConnectPrincipal.getSubjAttributes().getPersonalNumber());
                    claimsBuilder.claim("surname", swedenConnectPrincipal.getSubjAttributes().getSurname());
                    claimsBuilder.claim("givenName", swedenConnectPrincipal.getSubjAttributes().getGivenName());
                    claimsBuilder.claim("birthDate", swedenConnectPrincipal.getSubjAttributes().getBirthDate());
                }

                if (context.getPrincipal() instanceof PreAuthCodeGrantAuthenticationToken) {
                    SwedenConnectPrincipal swedenConnectPrincipal = ((PreAuthCodeGrantAuthenticationToken)context.getPrincipal()).getSwedenConnectPrincipal();
                    claimsBuilder.claim("personalNumber", swedenConnectPrincipal.getSubjAttributes().getPersonalNumber());
                    claimsBuilder.claim("surname", swedenConnectPrincipal.getSubjAttributes().getSurname());
                    claimsBuilder.claim("givenName", swedenConnectPrincipal.getSubjAttributes().getGivenName());
                    claimsBuilder.claim("birthDate", swedenConnectPrincipal.getSubjAttributes().getBirthDate());
                }

                claimsBuilder.claim("clientId", registeredClient.getClientId());

                claimsBuilder.subject(context.getPrincipal().getName()).audience(Collections.singletonList(registeredClient.getClientId())).issuedAt(issuedAt).expiresAt(expiresAt).id(UUID.randomUUID().toString());
                if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                    claimsBuilder.notBefore(issuedAt);
                    if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
                        claimsBuilder.claim("scope", context.getAuthorizedScopes());
                    }
                } else if ("id_token".equals(context.getTokenType().getValue())) {
                    claimsBuilder.claim("azp", registeredClient.getClientId());
                    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
                        OAuth2AuthorizationRequest authorizationRequest = (OAuth2AuthorizationRequest)context.getAuthorization().getAttribute(OAuth2AuthorizationRequest.class.getName());
                        String nonce = null;
                        if (authorizationRequest != null) {
                            nonce = (String)authorizationRequest.getAdditionalParameters().get("nonce");
                        }
                        if (StringUtils.hasText(nonce)) {
                            claimsBuilder.claim("nonce", nonce);
                        }

                        SessionInformation sessionInformation = (SessionInformation)context.get(SessionInformation.class);
                        if (sessionInformation != null) {
                            claimsBuilder.claim("sid", sessionInformation.getSessionId());
                            claimsBuilder.claim("auth_time", sessionInformation.getLastRequest());
                        }
                    } else if (AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType())) {
                        OidcIdToken currentIdToken = (OidcIdToken)context.getAuthorization().getToken(OidcIdToken.class).getToken();
                        if (currentIdToken.hasClaim("sid")) {
                            claimsBuilder.claim("sid", currentIdToken.getClaim("sid"));
                        }

                        if (currentIdToken.hasClaim("auth_time")) {
                            claimsBuilder.claim("auth_time", currentIdToken.getClaim("auth_time"));
                        }
                    }
                }

                JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);
                if (this.jwtCustomizer != null) {
                    JwtEncodingContext.Builder jwtContextBuilder = (JwtEncodingContext.Builder)((JwtEncodingContext.Builder)((JwtEncodingContext.Builder)((JwtEncodingContext.Builder)((JwtEncodingContext.Builder)((JwtEncodingContext.Builder)JwtEncodingContext.with(jwsHeaderBuilder, claimsBuilder).registeredClient(context.getRegisteredClient())).principal(context.getPrincipal())).authorizationServerContext(context.getAuthorizationServerContext())).authorizedScopes(context.getAuthorizedScopes())).tokenType(context.getTokenType())).authorizationGrantType(context.getAuthorizationGrantType());
                    if (context.getAuthorization() != null) {
                        jwtContextBuilder.authorization(context.getAuthorization());
                    }

                    if (context.getAuthorizationGrant() != null) {
                        jwtContextBuilder.authorizationGrant(context.getAuthorizationGrant());
                    }

                    if ("id_token".equals(context.getTokenType().getValue())) {
                        SessionInformation sessionInformation = (SessionInformation)context.get(SessionInformation.class);
                        if (sessionInformation != null) {
                            jwtContextBuilder.put(SessionInformation.class, sessionInformation);
                        }
                    }

                    JwtEncodingContext jwtContext = jwtContextBuilder.build();
                    this.jwtCustomizer.customize(jwtContext);
                }

                JwsHeader jwsHeader = jwsHeaderBuilder.build();
                JwtClaimsSet claims = claimsBuilder.build();
                Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
                return jwt;
            }
        } else {
            return null;
        }
    }

    public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
        this.jwtCustomizer = jwtCustomizer;
    }
}
