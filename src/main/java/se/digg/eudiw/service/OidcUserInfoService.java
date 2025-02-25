package se.digg.eudiw.service;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

public interface OidcUserInfoService {
    OidcUserInfo loadUser(String username);
}
