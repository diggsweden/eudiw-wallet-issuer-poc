package se.digg.eudiw.service;

import com.google.zxing.WriterException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URLEncodedUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.CredentialIssuanceRequest;
import se.digg.eudiw.model.CredentialOfferDeepLinkAndQrCode;
import se.digg.eudiw.model.ItbException;
import se.digg.eudiw.util.JwtIdUtil;
import se.oidc.oidfed.md.wallet.credentialissuer.AbstractCredentialConfiguration;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Service
public class EwcItbService {
  final URI callbackUri;
  final URI authzEndpoint;
  final URI tokenEndpoint;

  private static final Logger logger = LoggerFactory.getLogger(EwcItbService.class);
  private final EudiwConfig eudiwConfig;
  private final RestClient.Builder restClientBuilder;
  private final MetadataService metadataService;
  private final CredentialOfferService credentialOfferService;
  private final JwtIdUtil jwtIdUtil;

  Nonce nonce = new Nonce(); // move to request
  CodeVerifier pkceVerifier = new CodeVerifier(); // move to request

  public EwcItbService(EudiwConfig eudiwConfig, RestClient.Builder restClientBuilder,
      MetadataService metadataService,
      CredentialOfferService credentialOfferService, JwtIdUtil jwtIdUtil) {
    this.eudiwConfig = eudiwConfig;
    this.restClientBuilder = restClientBuilder;
    this.metadataService = metadataService;
    this.credentialOfferService = credentialOfferService;
    this.jwtIdUtil = jwtIdUtil;

    callbackUri = URI.create(String.format("%s/callback-ewc-itb", eudiwConfig.getIssuerBaseUrl()));
    authzEndpoint =
        URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
    tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));
  }

  public static String calculateOfferId(String sessionId) {
    // prefix external test session id´s in order to avoid collisions with real offer id´s
    return String.format("itb-%s", sessionId);
  }


  public CredentialIssuanceRequest initAuthFlow(String sessionId, List<String> credentialType)
      throws URISyntaxException, ParseException, JOSEException, IOException, WriterException {

    String credentialOfferFormId = calculateOfferId(sessionId);

    Set<String> requestedScopes = new HashSet<>();
    try {
      Map<String, AbstractCredentialConfiguration> credentialsSupported =
          metadataService.metadata().getCredentialConfigurationsSupported();
      if (credentialsSupported == null || credentialsSupported.isEmpty()) {
        throw new ItbException("fail", "Could not lookup supported credentials in issuer metadata",
            sessionId);
      }
      credentialType.forEach(ct -> {
        if (!credentialsSupported.containsKey(ct)) {
          throw new ItbException("fail", String.format("Credential type not supported: %s", ct),
              sessionId);
        }
        requestedScopes.add(credentialsSupported.get(ct).getScope());
      });

    } catch (CertificateEncodingException e) {
      throw new RuntimeException(e);
    }

    credentialOfferService.store(credentialOfferFormId, credentialType);

    // Generate new random string to link the callback to the authZ request
    // State state = new State();
    State state = new State(jwtIdUtil.id2jwt(credentialOfferFormId));

    Scope scope = new Scope();
    requestedScopes.forEach(scope::add);
    scope.add("openid");

    RestClient client = restClientBuilder
        .baseUrl(eudiwConfig.getCredentialHost())
        .build();

    ResponseEntity<String> result = client.get()
        .uri(uriBuilder -> uriBuilder
            .scheme(eudiwConfig.getIssuerConfig().scheme())
            .host(eudiwConfig.getIssuerConfig().host())
            .port(eudiwConfig.getIssuerConfig().port())
            .path("/oauth2/authorize")
            .queryParam("scope", scope.toString().replaceAll(" ", "+"))
            .queryParam("response_type", "code")
            .queryParam("redirect_uri", callbackUri)
            .queryParam("state", state)
            .queryParam("code_challenge_method", "S256")
            .queryParam("nonce", nonce)
            .queryParam("client_id", eudiwConfig.getClientId())
            .queryParam("code_challenge", pkceVerifier.getValue())
            .build())
        .retrieve().toEntity(String.class);

    if (result.getStatusCode() == HttpStatus.FOUND) {
      // Handle the redirect
      String loginLocation = Objects.requireNonNull(result.getHeaders().getLocation()).toString();
      logger.info("Redirecting to: {}", loginLocation);
      List<String> sessionCookieList = result.getHeaders().get("set-cookie");
      String[] sessionCookieArray =
          Objects.requireNonNull(sessionCookieList).toArray(new String[sessionCookieList.size()]);
      logger.info("cookie: {}", sessionCookieArray);

      ResponseEntity<String> idProxyResult = client.get()
          .uri(loginLocation)
          .header("Cookie", sessionCookieArray)
          .retrieve().toEntity(String.class);

      String idpLocation =
          Objects.requireNonNull(idProxyResult.getHeaders().getLocation()).toString();
      logger.info("idpLocation: {}", idpLocation);

      ResponseEntity<String> idpBackendResult = client.get()
          .uri(idpLocation)
          // .header("Cookie", sessionCookieArray)
          .retrieve().toEntity(String.class);

      List<String> authSessionCookieList = Objects.requireNonNull(
          idpBackendResult.getHeaders().get("set-cookie"));
      String[] authSessionCookieArray = Objects.requireNonNull(authSessionCookieList)
          .toArray(new String[authSessionCookieList.size()]);

      ArrayList<String> cookies = new ArrayList<>(Arrays.asList(sessionCookieArray));
      cookies.addAll(Arrays.asList(authSessionCookieArray));
      cookies.add("SERVERUSED=server1;");
      String[] cookiesArray = cookies.toArray(new String[0]);


      String idpFrontendLocation =
          Objects.requireNonNull(idpBackendResult.getHeaders().getLocation()).toString();
      logger.info("idpFrontendLocation: {}", idpFrontendLocation);

      client.get()
          .uri(idpFrontendLocation)
          // .header("Cookie", sessionCookieArray)
          .retrieve().toEntity(String.class);

      URI uri = new URI(idpFrontendLocation);
      List<NameValuePair> params = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);

      String idParsed = null;
      for (NameValuePair param : params) {
        if ("sp".equals(param.getName())) {
          param.getValue();
        } else if ("id".equals(param.getName())) {
          idParsed = param.getValue();
        }
      }

      final String id = idParsed;

      ResponseEntity<String> requestSessionFrontend = client.get()
          .uri(uriBuilder -> uriBuilder
              .scheme(eudiwConfig.getIdProxyFrontend().scheme())
              .host(eudiwConfig.getIdProxyFrontend().host())
              .port(eudiwConfig.getIdProxyFrontend().port())
              .path(eudiwConfig.getIdProxyFrontend().path("/api/request"))
              .queryParam("id", id)
              .queryParam("idp", eudiwConfig.getEwcItb().idp())
              .build())
          .header("Cookie", cookiesArray)
          .retrieve().toEntity(String.class);
      String requestSessionBackendLocation =
          Objects.requireNonNull(requestSessionFrontend.getHeaders().getLocation()).toString();
      logger.info("requestSessionBackendLocation: {}", requestSessionBackendLocation);

      ResponseEntity<String> requestSessionBackend = client.get()
          .uri(URI.create(requestSessionBackendLocation))
          .header("Cookie", cookiesArray)
          .retrieve().toEntity(String.class);


      String requestSessionLocation =
          Objects.requireNonNull(requestSessionBackend.getHeaders().getLocation()).toString();
      logger.info("requestSessionLocation: {}", requestSessionLocation);

      ResponseEntity<String> requestSession = client.get()
          .uri(URI.create(requestSessionLocation))
          .header("Cookie", cookiesArray)
          .retrieve().toEntity(String.class);

      String samlAuthnLocation =
          Objects.requireNonNull(requestSession.getHeaders().getLocation()).toString();

      ResponseEntity<String> samlAuthnReq = client.get()
          .uri(URI.create(samlAuthnLocation))
          .header("Cookie", cookiesArray)
          .retrieve().toEntity(String.class);

      List<String> extAuthSessionList = Objects.requireNonNull(
          samlAuthnReq.getHeaders().get("set-cookie"));
      Objects.requireNonNull(authSessionCookieList)
          .toArray(new String[authSessionCookieList.size()]);

      cookies.addAll(extAuthSessionList);
      String[] cookiesArrayWithExtAuthSession = cookies.toArray(new String[0]);

      cookies.add("selectedUser=197705232382#http://id.elegnamnden.se/loa/1.0/loa2;");

      String[] cookiesArrayWithSelectedUser = cookies.toArray(new String[0]);

      String extAuthLocation =
          Objects.requireNonNull(samlAuthnReq.getHeaders().getLocation()).toString();

      client.get()
          .uri(extAuthLocation)
          .header("Cookie", cookiesArrayWithExtAuthSession)
          .retrieve().toEntity(String.class);

      MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
      formData.add("signMessageDisplayed", "false");
      formData.add("personalIdentityNumber", "197705232382");
      formData.add("customPersonalIdentityNumber", "");
      formData.add("givenName", "Frida");
      formData.add("surname", "Kranstege");
      formData.add("loa", "http://id.elegnamnden.se/loa/1.0/loa2");
      formData.add("action", "ok");
      formData.add("mainError", "urn:oasis:names:tc:SAML:2.0:status:Responder");
      formData.add("subError", "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
      formData.add("errorMessage", "");

      ResponseEntity<String> extAuthCompleteReq = client.post()
          .uri(String.format("%s%s", eudiwConfig.getReferenceIdp().baseUrl(), "/extauth/complete"))
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(formData)
          .header("Cookie", cookiesArrayWithSelectedUser)
          .retrieve().toEntity(String.class);


      String resumeLocation =
          Objects.requireNonNull(extAuthCompleteReq.getHeaders().getLocation()).toString();

      ResponseEntity<String> resumeReq = client.get()
          .uri(resumeLocation)
          .header("Cookie", cookiesArrayWithExtAuthSession)
          .retrieve().toEntity(String.class);

      FormData resumeData = parseForm(resumeReq.getBody());


      MultiValueMap<String, String> resumeFormData = new LinkedMultiValueMap<>();
      resumeData.hiddenInputs.forEach(resumeFormData::add);

      ResponseEntity<String> authResponseReq = client.post()
          .uri(resumeData.action)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(resumeFormData)
          .header("Cookie", cookiesArrayWithExtAuthSession)
          .retrieve().toEntity(String.class);


      String authResponseSessionLocation =
          Objects.requireNonNull(authResponseReq.getHeaders().getLocation()).toString();
      ResponseEntity<String> authResponseSessionReq = client.get()
          .uri(authResponseSessionLocation)
          .header("Cookie", cookiesArrayWithExtAuthSession)
          .retrieve().toEntity(String.class);

      FormData authResponseSessionData = parseForm(authResponseSessionReq.getBody());

      MultiValueMap<String, String> returnData = new LinkedMultiValueMap<>();
      authResponseSessionData.hiddenInputs.forEach(returnData::add);

      ResponseEntity<String> returnReq = client.post()
          .uri(authResponseSessionData.action)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(returnData)
          .header("Cookie", cookiesArrayWithExtAuthSession)
          .retrieve().toEntity(String.class);

      String returnReqLocation =
          Objects.requireNonNull(returnReq.getHeaders().getLocation()).toString();
      ResponseEntity<String> resumeAuth = client.get()
          .uri(returnReqLocation)
          .header("Cookie", cookiesArrayWithExtAuthSession)
          .retrieve().toEntity(String.class);

      String redirectUriLocation =
          Objects.requireNonNull(resumeAuth.getHeaders().getLocation()).toString();

      URI redirectUri = new URI(redirectUriLocation);
      List<NameValuePair> redirectUriParams =
          URLEncodedUtils.parse(redirectUri, StandardCharsets.UTF_8);

      String authCodeParsed = null;
      String stateParsed = null;
      for (NameValuePair param : redirectUriParams) {
        if ("code".equals(param.getName())) {
          authCodeParsed = param.getValue();
        } else if ("state".equals(param.getName())) {
          stateParsed = param.getValue();
        }
      }

      final String codeParam = authCodeParsed;
      final String stateParam = stateParsed;

      String credentialOfferId =
          credentialOfferService.createCredentialOffer(pkceVerifier, codeParam, stateParam,
              callbackUri);

      CredentialOfferDeepLinkAndQrCode offer =
          credentialOfferService.credentialOfferDeepLinkAndQrCode(credentialOfferId);


      return new CredentialIssuanceRequest(
          String.format("data:image/jpeg;base64, %s", offer.qrCodeBase64()), sessionId);
    }

    throw new RuntimeException("Failed to initiate auth flow, status: " + result.getStatusCode());
  }


  public FormData parseForm(String htmlContent) {
    Document doc = Jsoup.parse(htmlContent);

    // Find the first form (or specify a selector for specific form)
    Element form = doc.selectFirst("form");
    if (form == null) {
      throw new RuntimeException("No form found in HTML");
    }

    // Get form action
    String action = form.attr("action");
    String method = form.attr("method");

    // Parse hidden inputs
    Map<String, String> hiddenInputs = new HashMap<>();
    Elements hiddenInputElements = form.select("input[type=hidden]");

    for (Element input : hiddenInputElements) {
      String name = input.attr("name");
      String value = input.attr("value");
      if (!name.isEmpty()) {
        hiddenInputs.put(name, value);
      }
    }

    return new FormData(action, method, hiddenInputs);
  }

  // Data class to hold form information
  public static class FormData {
    private final String action;
    private final String method;
    private final Map<String, String> hiddenInputs;

    public FormData(String action, String method, Map<String, String> hiddenInputs) {
      this.action = action;
      this.method = method;
      this.hiddenInputs = hiddenInputs;
    }

    // Getters
    public String getAction() {
      return action;
    }

    public String getMethod() {
      return method;
    }

    public Map<String, String> getHiddenInputs() {
      return hiddenInputs;
    }

    @Override
    public String toString() {
      return "FormData{action='" + action + "', method='" + method +
          "', hiddenInputs=" + hiddenInputs + "}";
    }
  }
}
