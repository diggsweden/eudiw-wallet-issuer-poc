package se.digg.eudiw.authentication;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.web.exchanges.HttpExchange.Principal;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import se.digg.eudiw.context.EudiwSessionSecurityContextRepository;
import se.swedenconnect.auth.commons.dto.ClientAuthResponse;

public class SwedenconnectAuthenticationReturnFilter extends AbstractAuthenticationProcessingFilter {

    private static final String SC_AUTH_PARAMETER_KEY = "response";

    Logger logger = LoggerFactory.getLogger(SwedenconnectAuthenticationReturnFilter.class);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/auth/return/**",
			"POST");

    public SwedenconnectAuthenticationReturnFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public SwedenconnectAuthenticationReturnFilter(AuthenticationManager authenticationManager, EudiwSessionSecurityContextRepository eudiwSessionSecurityContextRepository) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.setSecurityContextRepository(eudiwSessionSecurityContextRepository);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        logger.info("attemptAuthentication");
        if (HttpMethod.POST.name().equals(((HttpServletRequest)request).getMethod()) && DEFAULT_ANT_PATH_REQUEST_MATCHER.matches((HttpServletRequest)request)) {
            logger.info("matched url");
            try {         
                String authResponse = request.getParameter(SC_AUTH_PARAMETER_KEY);
                
                if (authResponse != null) {
                    byte[] decodedJsonBytes = Base64.getDecoder().decode(authResponse);

                    ClientAuthResponse responseData = OBJECT_MAPPER.readValue(decodedJsonBytes, ClientAuthResponse.class);
                    SwedenConnectAuthenticationToken token = new SwedenConnectAuthenticationToken(new Principal("swedenconnnect"), responseData, List.of(new SimpleGrantedAuthority("USER")));
                    logger.info("SC Auth {}: {} token: {}", SC_AUTH_PARAMETER_KEY, responseData, token);

                    setDetails(request, token);

                    return getAuthenticationManager().authenticate(token);
                }
            }
            catch (RuntimeException e) {
                String errorMessage = "Invalid response from IDProxy";
                logger.error("{} error:", errorMessage, e);
                throw new AuthenticationServiceException(errorMessage);
            }
        }

        //IdProxyRequestBuilder idProxyRequestBuilder = new IdProxyRequestBuilder();
        //String id = UUID.randomUUID().toString();
        //this.redirectStrategy.sendRedirect(request, response, idProxyRequestBuilder.buildAuthenticationRequest(id));
        return null;
    }


    protected void setDetails(HttpServletRequest request, SwedenConnectAuthenticationToken authRequest) {
		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}

}