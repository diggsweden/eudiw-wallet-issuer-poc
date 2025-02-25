package se.digg.eudiw.service;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class OidcUserInfoServiceImpl implements OidcUserInfoService {
    @Override
    public OidcUserInfo loadUser(String username) {
        return OidcUserInfo.builder()
                .subject(username)
                .name("First Last")
                .givenName("First")
                .familyName("Last")
                .middleName("Middle")
                .nickname("User")
                .preferredUsername(username)
                .profile("https://example.com/" + username)
                .picture("https://example.com/" + username + ".jpg")
                .website("https://example.com")
                .email(username + "@example.com")
                .emailVerified(true)
                .gender("female")
                .birthdate("1970-01-01")
                .zoneinfo("Europe/Paris")
                .locale("en-US")
                .phoneNumber("+1 (604) 555-1234;ext=5678")
                .phoneNumberVerified(false)
                .claim("address", Map.of("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
                .updatedAt("1970-01-01T00:00:00Z")
                .build();
    }
}
