package se.digg.eudiw.authorization;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;
import se.digg.eudiw.service.CredentialOfferService;
import se.digg.eudiw.service.DummyProofService;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

public class PreAuthCodeGrantAuthenticationConverter implements AuthenticationConverter {
    private final CredentialOfferService credentialOfferService;
    private final DummyProofService dummyProofService;
    Logger logger = LoggerFactory.getLogger(PreAuthCodeGrantAuthenticationConverter.class);

    public PreAuthCodeGrantAuthenticationConverter(CredentialOfferService credentialOfferService, DummyProofService dummyProofService) {
        this.credentialOfferService = credentialOfferService;
        this.dummyProofService = dummyProofService;
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
        //String oauthClientAttestationPop = request.getHeader("oauth-client-attestation-pop");
        String oauthClientAttestation = request.getHeader("oauth-client-attestation");
        logger.info("oauth-client-attestation-pop = {}", oauthClientAttestation);
        logger.info("oauth-client-attestation = {}", oauthClientAttestation);
        MultiValueMap<String, String> parameters = getParameters(request);

        if (oauthClientAttestation != null) {
            if (oauthClientAttestation.indexOf("~")>0) {
                oauthClientAttestation = oauthClientAttestation.split("~")[0];
            }

            try {
                SignedJWT signedJWT = SignedJWT.parse(oauthClientAttestation);
                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
                JWSHeader header = signedJWT.getHeader();
                if ("wallet-unit-attestation+jwt".equals(header.getType().getType())) {
                    String sub = jwtClaimsSet.getSubject();
                    Object cnf = jwtClaimsSet.getClaim("cnf");
                    logger.info("cnf: {}", cnf);
                    if (cnf instanceof LinkedTreeMap) {
                        JWK cnfJwk = JWK.parse(((LinkedTreeMap<String, LinkedTreeMap<String, Object>>)cnf).get("jwk"));
                        logger.info("cnf: {} -> {}", sub, cnfJwk);
                        // TODO: this has to be checked with wallet-provider
                        // now a temporary work-around in order to test iGrant

                        dummyProofService.storeJwk(sub, cnfJwk);
                    }

                }


            } catch (ParseException e) {
                logger.info("No proof is parsed in credential request");
            }

        }

        // code (REQUIRED)
        String preAuthorizedCode = parameters.getFirst(PreAuthParameterNames.PRE_AUTHORIZED_CODE);
        if (!StringUtils.hasText(preAuthorizedCode) ||
                parameters.get(PreAuthParameterNames.PRE_AUTHORIZED_CODE).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        PendingPreAuthorization pendingPreAuthorization = credentialOfferService.pendingPreAuthorization(preAuthorizedCode);

        String clientId = pendingPreAuthorization.getClientId();
        if (!StringUtils.hasText(clientId)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        String pendingTxCode = pendingPreAuthorization.getTxCode();

        String txCode = parameters.getFirst("tx_code");
        if (StringUtils.hasText(txCode)) {
            if (parameters.get("tx_code").size() != 1) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }

            if (!txCode.equals(pendingTxCode)) {
                logger.info("invalid txCode: {} TODO: replace this log with exception later on ", txCode);
            }
        }

        String userPin = parameters.getFirst("user_pin");
        if (StringUtils.hasText(userPin)) {
            if (parameters.get("user_pin").size() != 1) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
            if (!userPin.equals(pendingTxCode)) {
                logger.info("invalid userPin: {} TODO: replace this log with exception later on", userPin);
            }
        }

        if (!StringUtils.hasText(userPin) && !StringUtils.hasText(txCode) && StringUtils.hasText(pendingTxCode)) {
            logger.info("missing txCode: this credential offer require a txCode. TODO replace this log with exception later on");
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(PreAuthParameterNames.PRE_AUTHORIZED_CODE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        return new PreAuthCodeGrantAuthenticationToken(preAuthorizedCode, clientId, clientPrincipal, additionalParameters, pendingPreAuthorization.getPrincipal());
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
