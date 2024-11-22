package se.digg.eudiw.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.List;

@ConfigurationProperties(prefix="eudiw")
@Configuration
@Component 
public class EudiwConfig {

    private String authHost;

    private String callbackUrl;

    private String issuer;

    private String issuerBaseUrl;

    private String credentialHost;

    private int expHours;

    private String clientId;

    private List<String> redirectUris;

    private String oidFederationBaseUrl;

    private String issuerSignerKeyPemFile;

    public String getAuthHost() {
        return authHost;
    }

    public void setAuthHost(String authHost) {
        this.authHost = authHost;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }


    public String getIssuer() {
        return issuer;
    }

    public String getCredentialHost() {
        return credentialHost;
    }

    public int getExpHours() {
        return expHours;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuerBaseUrl() {
        return issuerBaseUrl;
    }

    public void setIssuerBaseUrl(String issuerBaseUrl) {
        this.issuerBaseUrl = issuerBaseUrl;
    }

    public void setCredentialHost(String credentialHost) {
        this.credentialHost = credentialHost;
    }

    public void setExpHours(int expHours) {
        this.expHours = expHours;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getOidFederationBaseUrl() {
        return oidFederationBaseUrl;
    }

    public void setOidFederationBaseUrl(String oidFederationBaseUrl) {
        this.oidFederationBaseUrl = oidFederationBaseUrl;
    }

    public String getIssuerSignerKeyPemFile() {
        return issuerSignerKeyPemFile;
    }

    public void setIssuerSignerKeyPemFile(String issuerSignerKeyPemFile) {
        this.issuerSignerKeyPemFile = issuerSignerKeyPemFile;
    }

    @Override
    public String toString() {
        return "EudiwConfig{" +
                "authHost='" + authHost + '\'' +
                ", callbackUrl='" + callbackUrl + '\'' +
                ", issuer='" + issuer + '\'' +
                ", issuerBaseUrl='" + issuerBaseUrl + '\'' +
                ", credentialHost='" + credentialHost + '\'' +
                ", expHours=" + expHours +
                ", clientId='" + clientId + '\'' +
                ", redirectUris=" + redirectUris +
                ", oidFederationBaseUrl='" + oidFederationBaseUrl + '\'' +
                ", issuerSignerKeyPemFile='" + issuerSignerKeyPemFile + '\'' +
                '}';
    }
}
