package se.digg.eudiw.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.TxCodeInputMode;
import se.digg.eudiw.model.credentialissuer.TxCodeType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Controller
@SessionAttributes("codeVerifier")
public class PidPreAuthCredentialOfferController {
    Logger logger = LoggerFactory.getLogger(PidPreAuthCredentialOfferController.class);

    final URI callbackUri;
    final URI authzEndpoint;
    final URI tokenEndpoint;

    Nonce nonce = new Nonce(); // move to request
    CodeVerifier pkceVerifier = new CodeVerifier(); // move to request

	private EudiwConfig eudiwConfig;

    PidPreAuthCredentialOfferController(@Autowired EudiwConfig eudiwConfig) {
        logger.info("PreAuthController created");
        this.eudiwConfig = eudiwConfig;

        callbackUri = URI.create(String.format("%s/pid/preauth", eudiwConfig.getIssuerBaseUrl()));
        authzEndpoint = URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
        tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));

    }

    /**
     * Initialize auth in pre-auth flow
     * @return
     * @throws URISyntaxException
     */
    @GetMapping("/pid/preauth")
    public ModelAndView initPreAuthPid(@ModelAttribute("codeVerifier") CodeVerifier pkceVerifier, @RequestParam("code") Optional<String> codeParam, @RequestParam("state") Optional<String> state, Model model) throws URISyntaxException {

        if (codeParam.isEmpty() || codeParam.get().isEmpty()) {
            // Generate new random string to link the callback to the authZ request
            State newState = new State();

            Scope scope = new Scope();
            scope.add("eu.europa.ec.eudi.pid.1");
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

            //String redirectUri = request.toURI().toString();
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

        ModelAndView modelAndView = new ModelAndView("pid-pre-auth-credential-offer");

        QRCodeWriter qrCodeWriter = new QRCodeWriter();

        CredentialOfferParam credentialOfferParam = new CredentialOfferParam(eudiwConfig.getIssuer(), List.of("eu.europa.ec.eudi.pid_mdoc", "eu.europa.ec.eudi.pid_jwt_vc_json"));
        credentialOfferParam.setGrants(Map.of(se.digg.eudiw.model.credentialissuer.GrantType.PRE_AUTHORIZED_CODE, new se.digg.eudiw.model.credentialissuer.PreAuthorizationCodeGrant(codeParam.get(), eudiwConfig.getAuthHost(), new TxCodeType(TxCodeInputMode.NUMERIC, 6, "PIN"))));

        String jsonData = null;
        try {

            jsonData = new ObjectMapper().writeValueAsString(credentialOfferParam);

            String credOffer = String.format("openid-credential-offer://credential_offer?credential_offer=%s", URLEncoder.encode(jsonData, StandardCharsets.UTF_8));
            logger.info("Creating QR code for credential offer: {}", credOffer);
            BitMatrix bitMatrix = qrCodeWriter.encode(credOffer, BarcodeFormat.QR_CODE, 300, 300);

            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageConfig con = new MatrixToImageConfig();

            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream,con);
            byte[] pngData = pngOutputStream.toByteArray();
            String qrCode = Base64.getEncoder().encodeToString(pngData);

            modelAndView.getModelMap().addAttribute("qrCode", String.format("data:image/jpeg;base64, %s", qrCode));
            modelAndView.getModelMap().addAttribute("linkUrl", credOffer);
            return modelAndView;
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        } catch (WriterException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @ModelAttribute("codeVerifier")
    public CodeVerifier codeVerifier() {
        return  new CodeVerifier();
    }


      protected static class PreAuthCodeAuthorizationGrant extends AuthorizationGrant {
          private final AuthorizationCode code;
          private final URI redirectURI;
          private final CodeVerifier pkceVerifier;
          private static final GrantType GRANT_TYPE = new GrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code");

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
