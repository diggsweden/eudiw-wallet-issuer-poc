package se.digg.eudiw.authorization;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Collection;
import java.util.Map;

public class PreAuthCodeGrantAuthenticationToken extends AbstractAuthenticationToken {


    private final String preAuthorizedCode;
    private final String clientId;
    private final Authentication authentication;
    private final Map<String, Object> additionalParameters;
    private final AuthorizationGrantType authorizationGrantType;

    public PreAuthCodeGrantAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        preAuthorizedCode = "";
        authentication = null;
        additionalParameters = Map.of();
        this.authorizationGrantType = new AuthorizationGrantType(PreAuthParameterNames.PRE_AUTHORIZED_CODE_GRANT);
        clientId = null;
    }

    public PreAuthCodeGrantAuthenticationToken(String preAuthorizedCode, String clientId, Authentication authentication, Map<String, Object> additionalParameters) {
        super(authentication.getAuthorities());
        this.preAuthorizedCode = preAuthorizedCode;
        this.clientId = clientId;
        this.authentication = authentication;
        this.additionalParameters = additionalParameters;
        this.authorizationGrantType = new AuthorizationGrantType(PreAuthParameterNames.PRE_AUTHORIZED_CODE_GRANT);
    }

    @Override
    public Object getCredentials() {
        return authentication.getCredentials();
    }

    @Override
    public Object getPrincipal() {
        return authentication.getPrincipal();
    }

    public String getPreAuthorizedCode() {
        return preAuthorizedCode;
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    public AuthorizationGrantType getGrantType() {
        return authorizationGrantType;
    }

    public String getClientId() {
        return clientId;
    }

    public AuthorizationGrantType getAuthorizationGrantType() {
        return authorizationGrantType;
    }
}
