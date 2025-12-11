package se.digg.eudiw.config;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpHost;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

  @Value("${proxy.host:}")
  private String proxyHost;

  @Value("${proxy.port:0}")
  private int proxyPort;

  @Value("${proxy.username:}")
  private String proxyUsername;

  @Value("${proxy.password:}")
  private String proxyPassword;

  @Bean
  @Primary
  public RestClient.Builder restClientBuilder() {
    HttpComponentsClientHttpRequestFactory factory =
        new HttpComponentsClientHttpRequestFactory();

    RequestConfig.Builder requestConfigBuilder = RequestConfig.custom()
        .setRedirectsEnabled(false);

    if (!proxyHost.isEmpty() && proxyPort > 0) {
      HttpHost proxy = new HttpHost(proxyHost, proxyPort);
      requestConfigBuilder.setProxy(proxy);
    }

    HttpClientBuilder httpClientBuilder = HttpClients.custom()
        .setDefaultRequestConfig(requestConfigBuilder.setRedirectsEnabled(false).build())
        .disableRedirectHandling().disableCookieManagement();

    if (!proxyUsername.isEmpty()) {
      BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
      credentialsProvider.setCredentials(
          new AuthScope(proxyHost, proxyPort),
          new UsernamePasswordCredentials(proxyUsername, proxyPassword.toCharArray()));
      httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
    }

    factory.setHttpClient(httpClientBuilder.build());

    return RestClient.builder().requestFactory(factory);
  }

}
