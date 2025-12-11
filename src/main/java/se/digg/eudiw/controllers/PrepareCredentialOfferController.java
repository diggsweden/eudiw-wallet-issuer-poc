package se.digg.eudiw.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.WriterException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.config.SignerConfig;
import se.digg.eudiw.model.CredentialOfferDeepLinkAndQrCode;
import se.digg.eudiw.model.CredentialOfferFormParam;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.GrantType;
import se.digg.eudiw.model.credentialissuer.AuthorizationCodeGrant;
import se.digg.eudiw.service.CredentialOfferService;
import se.digg.eudiw.service.MetadataService;
import se.digg.eudiw.util.IssuerStateBuilder;
import se.digg.eudiw.util.JwtIdUtil;
import se.oidc.oidfed.md.wallet.credentialissuer.AbstractCredentialConfiguration;
import se.oidc.oidfed.md.wallet.credentialissuer.Display;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

@Controller
public class PrepareCredentialOfferController {
  private static final Logger logger =
      LoggerFactory.getLogger(PrepareCredentialOfferController.class);

  private final CredentialOfferService credentialOfferService;
  private final SignerConfig signer;
  private final JwtIdUtil jwtIdUtil;

  final URI authzEndpoint;
  final URI tokenEndpoint;
  private final EudiwConfig eudiwConfig;
  private final PkiCredential issuerCredential;

  Map<String, AbstractCredentialConfiguration> credentialsSupported;
  Nonce nonce = new Nonce(); // move to request
  Random rnd;

  public PrepareCredentialOfferController(EudiwConfig eudiwConfig,
      CredentialBundles credentialBundles, MetadataService metadataService,
      CredentialOfferService credentialOfferService, SignerConfig signer, JwtIdUtil jwtIdUtil) {
    this.eudiwConfig = eudiwConfig;

    issuerCredential = credentialBundles.getCredential("issuercredential");
    authzEndpoint =
        URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
    tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));
    this.signer = signer;
    this.jwtIdUtil = jwtIdUtil;
    rnd = new Random();

    try {
      credentialsSupported = metadataService.metadata().getCredentialConfigurationsSupported();

    } catch (CertificateEncodingException | JOSEException | JsonProcessingException e) {
      throw new RuntimeException(e);
    }
    this.credentialOfferService = credentialOfferService;
  }

  @GetMapping("/credential_offer")
  public ModelAndView credentialOffer(@ModelAttribute("credentialOfferId") String credentialOfferId,
      Model model) {
    try {
      if (credentialOfferId == null || credentialOfferId.isEmpty()) {
        logger.info("No credential offer id provided - redirect to prepare credential offer page");
        return new ModelAndView("redirect:/prepare-credential-offer");
      }

      CredentialOfferDeepLinkAndQrCode offer =
          credentialOfferService.credentialOfferDeepLinkAndQrCode(credentialOfferId);

      model.addAttribute("qrCode",
          String.format("data:image/jpeg;base64, %s", offer.qrCodeBase64()));
      model.addAttribute("linkUrl", offer.deepLinkUrl());

      return new ModelAndView("credential-offer", model.asMap());
    } catch (WriterException | IOException e) {
      logger.error("Error creating QR code for credential offer", e);
      return new ModelAndView("redirect:/prepare-credential-offer");
    }
  }

  @GetMapping("/prepare-credential-offer")
  public ModelAndView prepareCredentialOffer(
      @ModelAttribute("credentialOffer") CredentialOfferFormParam credentialOffer, Model model) {
    List<String> availableCredentials = credentialsSupported.keySet().stream().toList();
    model.addAttribute("credentialOffer",
        new CredentialOfferFormParam(true, availableCredentials, new ArrayList<>(), null));
    model.addAttribute("credentialsSupported", credentialsSupported);

    Map<String, Display> display = credentialsSupported.entrySet().stream().map(entry -> {
      String key = entry.getKey();
      AbstractCredentialConfiguration value = entry.getValue();
      Display d = getDisplay(value, "en");
      return Map.entry(key, d);
    }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    model.addAttribute("display", display);

    return new ModelAndView("prepare-credential-offer");
  }

  @PostMapping("/prepare-credential-offer")
  public ModelAndView prepareCredentialOffer(
      @ModelAttribute CredentialOfferFormParam credentialOffer, Model model,
      RedirectAttributes redirectAttributes) {

    model.addAttribute("credentialOffer", credentialOffer);

    if (credentialOffer.isCompleteAndValid()) {

      redirectAttributes.addFlashAttribute("credentialOffer", credentialOffer);
      if (credentialOffer.isPreAuthCodeFlow()) {
        return new ModelAndView("redirect:/pre-auth-credential-offer");
      }

      String credentialOfferId = UUID.randomUUID().toString();

      CredentialOfferParam credentialOfferParam = new CredentialOfferParam(eudiwConfig.getIssuer(),
          new ArrayList<>(credentialOffer.getSelectedCredentials()));
      IssuerStateBuilder issuerStateBuilder =
          new IssuerStateBuilder(eudiwConfig.getIssuer(), issuerCredential);
      issuerStateBuilder.withCredentialOfferId(UUID.randomUUID().toString());
      credentialOfferParam.setGrants(Map.of(GrantType.AUTHORIZATION_CODE,
          new AuthorizationCodeGrant(issuerStateBuilder.build(), eudiwConfig.getAuthHost())));
      credentialOfferService.store(credentialOfferId, credentialOfferParam);

      redirectAttributes.addFlashAttribute("credentialOfferId", credentialOfferId);
      return new ModelAndView("redirect:/credential_offer");
    } else {
      credentialOffer.setMessage("Minst ett pid format måste markeras");
    }

    List<String> availableCredentials = credentialsSupported.keySet().stream().toList();
    model.addAttribute("credentialOffer",
        new CredentialOfferFormParam(true, availableCredentials, new ArrayList<>(), null));
    model.addAttribute("credentialsSupported", credentialsSupported);

    Map<String, Display> display = credentialsSupported.entrySet().stream().map(entry -> {
      String key = entry.getKey();
      AbstractCredentialConfiguration value = entry.getValue();
      Display d = getDisplay(value, "en");
      return Map.entry(key, d);
    }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    model.addAttribute("display", display);

    return new ModelAndView("prepare-credential-offer", model.asMap());
  }

  @GetMapping("/pre-auth-credential-offer")
  public ModelAndView initPreAuthPid(
      @ModelAttribute("credentialOffer") CredentialOfferFormParam credentialOffer,
      @ModelAttribute("codeVerifier") CodeVerifier pkceVerifier,
      @RequestParam("code") Optional<String> codeParam,
      @RequestParam("state") Optional<String> state, Model model,
      RedirectAttributes redirectAttributes)
      throws URISyntaxException, JOSEException, ParseException, IOException, WriterException {

    URI callbackUri =
        URI.create(String.format("%s/pre-auth-credential-offer", eudiwConfig.getIssuerBaseUrl()));

    if (codeParam.isEmpty() || codeParam.get().isEmpty()) {
      String credentialOfferFormId = UUID.randomUUID().toString();

      // Generate new random string to link the callback to the authZ request
      State newState = new State(jwtIdUtil.id2jwt(credentialOfferFormId));
      Scope scope = new Scope();
      credentialOffer.getSelectedCredentials().forEach(cred -> {
        String newScope = credentialsSupported.get(cred).getScope();
        if (!scope.contains(newScope)) {
          logger.info("Adding scope {} for credential: {} ", newScope, cred);
          scope.add(newScope);
        }
      });
      scope.add("openid");


      AuthenticationRequest request = new AuthenticationRequest.Builder(
          new ResponseType("code"),
          scope,
          new ClientID(eudiwConfig.getClientId()),
          callbackUri)
          .endpointURI(authzEndpoint)
          .state(newState)
          .nonce(nonce)
          .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
          .build();

      Map<String, List<String>> params = request.toParameters();
      URI redirectUri = request.getEndpointURI();
      logger.info("Redirecting to: " + redirectUri);
      ModelMap modelMap = new ModelMap();
      modelMap.addAllAttributes(params);
      credentialOfferService.store(credentialOfferFormId, credentialOffer.getSelectedCredentials());
      return new ModelAndView(String.format("redirect:%s", redirectUri), modelMap);
    }

    String credentialOfferId = credentialOfferService.createCredentialOffer(pkceVerifier,
        codeParam.get(), state.get(), callbackUri);
    redirectAttributes.addFlashAttribute("credentialOfferId", credentialOfferId);

    return new ModelAndView("redirect:/credential_offer");
  }


  private Display getDisplay(AbstractCredentialConfiguration credentialConfiguration,
      String locale) {
    return credentialConfiguration.getDisplay().stream().filter(d -> d.getLocale().equals(locale))
        .findFirst().orElse(credentialConfiguration.getDisplay().get(0));
  }
}
