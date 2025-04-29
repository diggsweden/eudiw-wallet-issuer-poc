package se.digg.eudiw.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import se.digg.eudiw.authentication.SwedenConnectPrincipal;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.CredentialOfferFormParam;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.GrantType;
import se.digg.eudiw.model.credentialissuer.AuthorizationCodeGrant;
import se.digg.eudiw.model.credentialissuer.TxCodeType;
import se.digg.eudiw.model.credentialissuer.TxCodeInputMode;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;
import se.digg.eudiw.service.CredentialOfferService;
import se.digg.eudiw.service.MetadataService;
import se.digg.eudiw.util.IssuerStateBuilder;
import se.oidc.oidfed.md.wallet.credentialissuer.AbstractCredentialConfiguration;
import se.oidc.oidfed.md.wallet.credentialissuer.Display;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.util.*;
import java.util.stream.Collectors;

@Controller
public class PrepareCredentialOfferController {
    private static final Logger logger = LoggerFactory.getLogger(PrepareCredentialOfferController.class);

    private final CredentialOfferService credentialOfferService;

    final URI callbackUri;
    final URI authzEndpoint;
    final URI tokenEndpoint;
    private final EudiwConfig eudiwConfig;
    private final PkiCredential issuerCredential;

    Map<String, AbstractCredentialConfiguration> credentialsSupported;
    Nonce nonce = new Nonce(); // move to request
    Random rnd;

    public PrepareCredentialOfferController(EudiwConfig eudiwConfig, CredentialBundles credentialBundles, MetadataService metadataService, CredentialOfferService credentialOfferService) {
        this.eudiwConfig = eudiwConfig;

        issuerCredential = credentialBundles.getCredential("issuercredential");
        callbackUri = URI.create(String.format("%s/pre-auth-credential-offer", eudiwConfig.getIssuerBaseUrl()));
        authzEndpoint = URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
        tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));
        rnd = new Random();

        try {
            credentialsSupported = metadataService.metadata().getCredentialConfigurationsSupported();

        } catch (CertificateEncodingException | JOSEException | JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        this.credentialOfferService = credentialOfferService;
    }

    @GetMapping("/credential_offer")
    public ModelAndView credentialOffer(@ModelAttribute("credentialOfferId") String credentialOfferId, Model model) {
        try {
            if (credentialOfferId == null || credentialOfferId.isEmpty()) {
                logger.info("No credential offer id provided - redirect to prepare credential offer page");
                return new ModelAndView("redirect:/prepare-credential-offer");
            }

            String credentialUrl = String.format("%s/credential_offer/%s", eudiwConfig.getIssuerBaseUrl(), credentialOfferId);
            String credOffer = String.format("openid-credential-offer://credential_offer?credential_offer_uri=%s", URLEncoder.encode(credentialUrl, StandardCharsets.UTF_8));
            logger.info("Creating QR code for credential offer: {}", credOffer);
            QRCodeWriter qrCodeWriter = new QRCodeWriter();

            BitMatrix bitMatrix = qrCodeWriter.encode(credOffer, BarcodeFormat.QR_CODE, 300, 300);

            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageConfig con = new MatrixToImageConfig();

            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream,con);
            byte[] pngData = pngOutputStream.toByteArray();
            String qrCode = Base64.getEncoder().encodeToString(pngData);

            model.addAttribute("qrCode", String.format("data:image/jpeg;base64, %s", qrCode));
            model.addAttribute("linkUrl", credOffer);

            return new ModelAndView("credential-offer", model.asMap());
        } catch (WriterException | IOException e) {
            logger.error("Error creating QR code for credential offer", e);
            return new ModelAndView("redirect:/prepare-credential-offer");
        }
    }

    @GetMapping("/prepare-credential-offer")
    public ModelAndView prepareCredentialOffer(@ModelAttribute("credentialOffer") CredentialOfferFormParam credentialOffer, Model model) {
        List<String> availableCredentials = credentialsSupported.keySet().stream().toList();
        model.addAttribute("credentialOffer", new CredentialOfferFormParam(true, availableCredentials, new ArrayList<>(), null));
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
    public ModelAndView prepareCredentialOffer(@ModelAttribute CredentialOfferFormParam credentialOffer, Model model, RedirectAttributes redirectAttributes) {

        model.addAttribute("credentialOffer", credentialOffer);

        if (credentialOffer.isCompleteAndValid()) {

            redirectAttributes.addFlashAttribute("credentialOffer", credentialOffer);
            if (credentialOffer.isPreAuthCodeFlow()) {
                return new ModelAndView("redirect:/pre-auth-credential-offer");
            }

            String credentialOfferId = UUID.randomUUID().toString();

            CredentialOfferParam credentialOfferParam = new CredentialOfferParam(eudiwConfig.getIssuer(), new ArrayList<>(credentialOffer.getSelectedCredentials()));
            IssuerStateBuilder issuerStateBuilder = new IssuerStateBuilder(eudiwConfig.getIssuer(), issuerCredential);
            issuerStateBuilder.withCredentialOfferId(UUID.randomUUID().toString());
            credentialOfferParam.setGrants(Map.of(GrantType.AUTHORIZATION_CODE, new AuthorizationCodeGrant(issuerStateBuilder.build(), eudiwConfig.getAuthHost())));
            credentialOfferService.store(credentialOfferId, credentialOfferParam);

            redirectAttributes.addFlashAttribute("credentialOfferId", credentialOfferId);
            return new ModelAndView("redirect:/credential_offer");
        }
        else {
            credentialOffer.setMessage("Minst ett pid format måste markeras");
        }

        List<String> availableCredentials = credentialsSupported.keySet().stream().toList();
        model.addAttribute("credentialOffer", new CredentialOfferFormParam(true, availableCredentials, new ArrayList<>(), null));
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
    public ModelAndView initPreAuthPid(@ModelAttribute("credentialOffer") CredentialOfferFormParam credentialOffer, @ModelAttribute("codeVerifier") CodeVerifier pkceVerifier, @RequestParam("code") Optional<String> codeParam, @RequestParam("state") Optional<String> state, Model model, RedirectAttributes redirectAttributes) throws URISyntaxException {

        if (codeParam.isEmpty() || codeParam.get().isEmpty()) {
            // Generate new random string to link the callback to the authZ request
            State newState = new State();

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

            return new ModelAndView(String.format("redirect:%s", redirectUri), modelMap);
        }

        logger.info("code: {}", codeParam);

        AuthorizationCode code = new AuthorizationCode(codeParam.get());
        AuthorizationGrant codeGrant = new PreAuthCodeAuthorizationGrant(code, callbackUri, pkceVerifier);

        logger.info("codeGrant: {}", codeGrant.toParameters());

        ClientID clientID = new ClientID(eudiwConfig.getClientId());

        CredentialOfferParam credentialOfferParam = new CredentialOfferParam(eudiwConfig.getIssuer(), List.of("eu.europa.ec.eudi.pid_jwt_vc_json"));
        credentialOfferParam.setGrants(Map.of(se.digg.eudiw.model.credentialissuer.GrantType.PRE_AUTHORIZED_CODE, new se.digg.eudiw.model.credentialissuer.PreAuthorizationCodeGrant(codeParam.get(), eudiwConfig.getAuthHost(), new TxCodeType(TxCodeInputMode.NUMERIC, 6, "PIN"))));

        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        SwedenConnectPrincipal swedenConnectPrincipal = null;
        Object principal = authentication.getPrincipal();
        if (principal instanceof SwedenConnectPrincipal) {
            swedenConnectPrincipal = (SwedenConnectPrincipal) principal;
        }

        if (swedenConnectPrincipal == null) {
            throw new RuntimeException("TODO handle not authenticated");
        }

        int number = rnd.nextInt(999999);

        String txCode = String.format("%06d", number);
        PendingPreAuthorization pendingPreAuthorization = new PendingPreAuthorization(credentialOfferParam, callbackUri.toString(), pkceVerifier, clientID.getValue(), txCode, swedenConnectPrincipal);
        credentialOfferService.store(code.getValue(), pendingPreAuthorization);

        logger.info("Pending Credential offer: {}", pendingPreAuthorization);

        String credentialOfferId = UUID.randomUUID().toString();
        credentialOfferService.store(credentialOfferId, credentialOfferParam);
        redirectAttributes.addFlashAttribute("credentialOfferId", credentialOfferId);

        return new ModelAndView("redirect:/credential_offer");
    }


    private Display getDisplay(AbstractCredentialConfiguration credentialConfiguration, String locale) {
        return credentialConfiguration.getDisplay().stream().filter(d -> d.getLocale().equals(locale)).findFirst().orElse(credentialConfiguration.getDisplay().get(0));
    }

    protected static class PreAuthCodeAuthorizationGrant extends AuthorizationGrant {
        private final AuthorizationCode code;
        private final URI redirectURI;
        private final CodeVerifier pkceVerifier;
        private static final com.nimbusds.oauth2.sdk.GrantType GRANT_TYPE = new com.nimbusds.oauth2.sdk.GrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code");

        PreAuthCodeAuthorizationGrant(AuthorizationCode code, URI redirectURI, CodeVerifier pkceVerifier) {
            super(GRANT_TYPE);
            this.code = code;
            this.redirectURI = redirectURI;
            this.pkceVerifier = pkceVerifier;
        }

        @Override
        public Map<String, List<String>> toParameters() {
            Map<String, List<String>> params = new LinkedHashMap();
            params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
            params.put("pre-authorized_code", Collections.singletonList(this.code.getValue()));
            params.put("code", Collections.singletonList(this.code.getValue()));
            if (this.redirectURI != null) {
                params.put("redirect_uri", Collections.singletonList(this.redirectURI.toString()));
                params.put("code_verifier", List.of(pkceVerifier.getValue()));
            }

            return params;
        }
    }

}
