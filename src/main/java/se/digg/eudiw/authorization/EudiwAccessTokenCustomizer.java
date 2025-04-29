package se.digg.eudiw.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import se.digg.eudiw.authentication.SwedenConnectPrincipal;

import java.util.Set;
import java.util.stream.Collectors;

public class EudiwAccessTokenCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
    public EudiwAccessTokenCustomizer() {
    }

    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        Authentication principal = context.getPrincipal();
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            context.getClaims().claim("authorities", authorities);

            // TODO det mesta borde flyttas till idToken eller userinfo någonting
            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
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

                claims.claim("client_id", context.getRegisteredClient().getClientId());

            }

        }
    }
}
