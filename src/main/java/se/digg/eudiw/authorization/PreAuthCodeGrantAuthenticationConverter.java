package se.digg.eudiw.authorization;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import se.digg.eudiw.context.EudiwSessionSecurityContextRepository;

import java.util.HashMap;
import java.util.Map;

public class PreAuthCodeGrantAuthenticationConverter implements AuthenticationConverter {
    private final EudiwSessionSecurityContextRepository securityContextRepository;
    Logger logger = LoggerFactory.getLogger(PreAuthCodeGrantAuthenticationConverter.class);

    public PreAuthCodeGrantAuthenticationConverter(EudiwSessionSecurityContextRepository securityContextRepository){
        this.securityContextRepository = securityContextRepository;
    }

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        logger.info("CONVERT {}", request);
        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        logger.info("grant type: {}", grantType);
        if (!"urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType)) {
            return null;
        }
        //DeferredSecurityContext deferredSecurityContext = securityContextRepository.loadDeferredContext(request);
        //Authentication clientPrincipal = deferredSecurityContext.get().getAuthentication();
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        MultiValueMap<String, String> parameters = getParameters(request);

        // code (REQUIRED)
        String preAuthorizedCode = parameters.getFirst(PreAuthParameterNames.PRE_AUTHORIZED_CODE);
        if (!StringUtils.hasText(preAuthorizedCode) ||
                parameters.get(PreAuthParameterNames.PRE_AUTHORIZED_CODE).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        String clientId = parameters.getFirst("client_id");
        if (!StringUtils.hasText(preAuthorizedCode) ||
                parameters.get("client_id").size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        String txCode = parameters.getFirst("tx_code");
        if (StringUtils.hasText(txCode)) {
            if (parameters.get("tx_code").size() != 1) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
            // todo verify that tx_code is valid
            logger.info("tx_code: {} TODO VERIFY!", txCode);
        }

        String userPin = parameters.getFirst("user_pin");
        if (StringUtils.hasText(userPin)) {
            if (parameters.get("user_pin").size() != 1) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
            // todo verify that EWC legacy userPin is valid - user_pin is replaced with tx_code in current spec
            logger.info("userPin: {} TODO VERIFY!", userPin);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(PreAuthParameterNames.PRE_AUTHORIZED_CODE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        return new PreAuthCodeGrantAuthenticationToken(preAuthorizedCode, clientId, clientPrincipal, additionalParameters);
        //return new OAuth2AuthorizationCodeAuthenticationToken(preAuthorizedCode, clientPrincipal, redirectUri, additionalParameters);
    }



    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }

}
