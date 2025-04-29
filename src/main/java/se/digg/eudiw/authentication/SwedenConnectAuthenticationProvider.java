package se.digg.eudiw.authentication;

import java.text.ParseException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.SignedJWT;

import se.digg.eudiw.context.EudiwSessionSecurityContextRepository;
import se.swedenconnect.auth.commons.dto.ClientAuthStatus;
import se.swedenconnect.auth.commons.idtoken.IdTokenClaims;
import se.swedenconnect.auth.commons.response.IdTokenValidationException;
import se.swedenconnect.auth.commons.response.IdTokenValidator;

@Component
public class SwedenConnectAuthenticationProvider implements AuthenticationProvider, AuthenticationManager {
    private final EudiwSessionSecurityContextRepository eudiwSessionSecurityContextRepository;
    Logger logger = LoggerFactory.getLogger(SwedenConnectAuthenticationProvider.class);

    @Autowired
    private IdTokenValidator idTokenValidator;

    public SwedenConnectAuthenticationProvider(@Autowired EudiwSessionSecurityContextRepository eudiwSessionSecurityContextRepository) {
        this.eudiwSessionSecurityContextRepository = eudiwSessionSecurityContextRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        logger.trace("authenticate with sweden connect");

        if (authentication instanceof SwedenConnectAuthenticationToken) {
            SwedenConnectAuthenticationToken authenticationToken = (SwedenConnectAuthenticationToken) authentication;

            if (authenticationToken.getCredentials() == null) {
                SwedenConnectAuthenticationToken token = new SwedenConnectAuthenticationToken(authenticationToken.getPrincipal(), authenticationToken.getCredentials(), authenticationToken.getAuthorities() );
                token.setDetails(
                        authenticationToken.getDetails()
                );
                logger.info("SwedenConnectAuthenticationToken exists in security context: {}", token);
                return token;
            }
            if (!ClientAuthStatus.OK.equals(authenticationToken.getCredentials().getStatus())) {
                AuthenticationException authException = new BadCredentialsException("Authentication failed");
                logger.info("Authentication failed with status: {}", authenticationToken.getCredentials().getStatus(), authException);
                // TODO decide AuthenticationException type based on status
                throw authException;
            }
            try {
                SignedJWT signedJWT = idTokenValidator.validateIdToken(authenticationToken.getCredentials().getIdToken());
                IdTokenClaims idTokenClaims = null;
                if (signedJWT != null) {
                    try {
                        idTokenClaims = idTokenValidator.getIdTokenClaims(signedJWT);

                        SwedenConnectAuthenticationToken token = new SwedenConnectAuthenticationToken(new SwedenConnectPrincipal(idTokenClaims.getSubjectAttributes()), authenticationToken.getCredentials(), List.of(new SimpleGrantedAuthority("USER")) );
                        token.setDetails(
                            authenticationToken.getDetails()
                        );
                        logger.info("Authenticated token: {}", token);

                        return token;
                    } catch (JsonProcessingException | ParseException e) { 
                        logger.error("Could not parse swedenconnect jwt", e);
                        throw new AuthenticationServiceException("Could not parse swedenconnect jwt", e);

                    } 
                }
            } catch (IdTokenValidationException e) {
                String swedenconnectJwtValidationFailed = "swedenconnect jwt validation failed";
                logger.error(swedenconnectJwtValidationFailed, e);
                throw new AuthenticationServiceException(swedenconnectJwtValidationFailed, e);
            }
        }
        logger.info("No swedenconnect authentication is returned {}", authentication.getName());
        throw new AuthenticationServiceException("No swedenconnect authentication is returned");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SwedenConnectAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
