package se.digg.eudiw.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.List;

@ConfigurationProperties(prefix = "eudiw")
@Configuration
@Component
public class EudiwConfig {

  public record OpenIdFederationConfiguration(String baseUrl, String trustMarkId, String subject,
      Integer trustListTtlInSeconds, String walletProviderAnchor, String walletBaseUri,
      List<String> authorityHints) {
  }

  public record SwedenConnectConfiguration(String baseUrl, String client, String returnBaseUrl) {
  }

  public record ValKeyConfig(String host, int port) {
  }

  public record EwcItbConfig(String idp) {
  }

  public record HttpProxyConfig(String host, int port, String noProxy) {
  }

  public record ServerBaseConfig(String host, int port, String scheme, String contextPath) {

    public String baseUrl() {
      return String.format("%s://%s%s%s", scheme, host,
          port == 80 || port == 443 || port == 0 ? "" : ":" + port,
          contextPath != null ? contextPath : "");
    }

    public String path(String subPath) {
      return String.format("%s%s", contextPath != null ? contextPath : "",
          subPath != null ? subPath : "");
    }
  }

  private String authHost;

  private String callbackUrl;

  private ServerBaseConfig issuerConfig;

  private ServerBaseConfig idProxyFrontend;

  private ServerBaseConfig referenceIdp;

  private String issuer;

  private String issuerBaseUrl;

  private String credentialHost;

  private int expHours;

  private String clientId;

  private List<String> redirectUris;

  private int credentialOfferTtlInSeconds;

  private boolean signedMetaData;

  private OpenIdFederationConfiguration openidFederation;

  private SwedenConnectConfiguration swedenconnect;

  private ValKeyConfig valkey;

  private EwcItbConfig ewcItb;

  private HttpProxyConfig httpProxy;

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

  public int getCredentialOfferTtlInSeconds() {
    return credentialOfferTtlInSeconds;
  }

  public void setCredentialOfferTtlInSeconds(int credentialOfferTtlInSeconds) {
    this.credentialOfferTtlInSeconds = credentialOfferTtlInSeconds;
  }

  public boolean isSignedMetaData() {
    return signedMetaData;
  }

  public void setSignedMetaData(boolean signedMetaData) {
    this.signedMetaData = signedMetaData;
  }

  public void setRedirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  public OpenIdFederationConfiguration getOpenidFederation() {
    return openidFederation;
  }

  public void setOpenidFederation(OpenIdFederationConfiguration oidFederation) {
    this.openidFederation = oidFederation;
  }

  public SwedenConnectConfiguration getSwedenconnect() {
    return swedenconnect;
  }

  public void setSwedenconnect(SwedenConnectConfiguration swedenconnect) {
    this.swedenconnect = swedenconnect;
  }

  public ValKeyConfig getValkey() {
    return valkey;
  }

  public void setValkey(ValKeyConfig valkey) {
    this.valkey = valkey;
  }

  public EwcItbConfig getEwcItb() {
    return ewcItb;
  }

  public void setEwcItb(EwcItbConfig ewcItb) {
    this.ewcItb = ewcItb;
  }

  public ServerBaseConfig getIssuerConfig() {
    return issuerConfig;
  }

  public void setIssuerConfig(ServerBaseConfig issuerConfig) {
    this.issuerConfig = issuerConfig;
  }

  public ServerBaseConfig getIdProxyFrontend() {
    return idProxyFrontend;
  }

  public void setIdProxyFrontend(ServerBaseConfig idProxyFrontend) {
    this.idProxyFrontend = idProxyFrontend;
  }

  public HttpProxyConfig getHttpProxy() {
    return httpProxy;
  }

  public void setHttpProxy(HttpProxyConfig httpProxy) {
    this.httpProxy = httpProxy;
  }

  public ServerBaseConfig getReferenceIdp() {
    return referenceIdp;
  }

  public void setReferenceIdp(ServerBaseConfig referenceIdp) {
    this.referenceIdp = referenceIdp;
  }

  @Override
  public String toString() {
    return "EudiwConfig{" +
        "authHost='" + authHost + '\'' +
        ", callbackUrl='" + callbackUrl + '\'' +
        ", issuerConfig=" + issuerConfig +
        ", idProxyFrontend=" + idProxyFrontend +
        ", referenceIdp=" + referenceIdp +
        ", issuer='" + issuer + '\'' +
        ", issuerBaseUrl='" + issuerBaseUrl + '\'' +
        ", credentialHost='" + credentialHost + '\'' +
        ", expHours=" + expHours +
        ", clientId='" + clientId + '\'' +
        ", redirectUris=" + redirectUris +
        ", credentialOfferTtlInSeconds=" + credentialOfferTtlInSeconds +
        ", signedMetaData=" + signedMetaData +
        ", openidFederation=" + openidFederation +
        ", swedenconnect=" + swedenconnect +
        ", valkey=" + valkey +
        '}';
  }
}
