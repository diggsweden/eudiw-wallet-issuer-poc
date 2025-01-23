package se.digg.eudiw.controllers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.Map;

import java.io.ByteArrayOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;

import jakarta.websocket.server.PathParam;
import se.digg.eudiw.config.EudiwConfig;

import org.springframework.web.servlet.view.RedirectView;

@Controller
public class PreAuthController {

    Logger logger = LoggerFactory.getLogger(PreAuthController.class);

    final URI callbackUri;
    final URI authzEndpoint;
    final URI tokenEndpoint;

    Nonce nonce = new Nonce(); // move to request
    CodeVerifier pkceVerifier = new CodeVerifier(); // move to request

	private final EudiwConfig eudiwConfig;

    PreAuthController(@Autowired EudiwConfig eudiwConfig) {
        logger.info("PreAuthController created");
        this.eudiwConfig = eudiwConfig;

        callbackUri = URI.create(String.format("%s/callback", eudiwConfig.getIssuerBaseUrl()));
        authzEndpoint = URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
        tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));
    }

    @GetMapping("/login")
    public RedirectView foo() throws URISyntaxException {

        // Generate new random string to link the callback to the authZ request
        State state = new State();

       Scope scope = new Scope();
       scope.add("VerifiablePortableDocumentA1");
       scope.add("openid");
       scope.add("profile");

        //Build the actual OAuth 2.0 authorisation request
        // AuthorizationRequest request = new AuthorizationRequest.Builder(
        //         new ResponseType("code"), 
        //         new ClientID(eudiwConfig.getClientId()))
        //     .endpointURI(authzEndpoint)
        //     .redirectionURI(callbackUri)
        //     .scope(new Scope("identitycredential.read"))
        //     .state(state)
        //     .customParameter("nonce", nonce.getValue())
        //     .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
        //     .build();

       
        AuthenticationRequest request = new AuthenticationRequest.Builder(
            new ResponseType("code"),
            scope,
            new ClientID(eudiwConfig.getClientId()),
            callbackUri)
            .endpointURI(authzEndpoint)
            .state(state)
            .nonce(nonce)
            .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
            .build();

        String redirectUri = request.toURI().toString();
        logger.info("Redirecting to: " + redirectUri);
    


        return new RedirectView(redirectUri);
    }

    @GetMapping(value = "/callback", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String welcomeAsHTML(@PathParam("code") String code, @PathParam("state") String state) throws Exception {
              if (pkceVerifier == null) {
                  throw new Exception("pkceVerifier is null");
              }
              if (nonce == null) {
                  throw new Exception("nonce is null");
              }
              logger.info("callback code: %s state: %s verifier: %s nonce: %s", code, state, pkceVerifier.getValue(), nonce.getValue());
              QRCodeWriter qrCodeWriter = new QRCodeWriter();
              Map<String, String> map = Map.of("code", code, "state", state, "verifier", pkceVerifier.getValue(), "nonce", nonce.getValue());
              String jsonData = new ObjectMapper().writeValueAsString(map);
              BitMatrix bitMatrix = qrCodeWriter.encode(jsonData, BarcodeFormat.QR_CODE, 300, 300);
      
              ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
              MatrixToImageConfig con = new MatrixToImageConfig();
      
              MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream,con);
              byte[] pngData = pngOutputStream.toByteArray();
              String qrcode = Base64.getEncoder().encodeToString(pngData);
              logger.info("QR code: " + qrcode);
              logger.info("QR code data: " + jsonData);
            
              return "<html>\n" + "<header><title>Logga in EUDIW wallet</title></header>\n" +
                     "<body>" +
                     "<h1>Logga in EUDIW wallet</h1>" +
                     "<p>Öppna EUDIW wallet och skanna QR-koden</p>" + 
                     "<img style='display:block; width:300px;height:300px;' id='base64image' src='data:image/jpeg;base64, " + qrcode + "'></img>" + 
                     "</body>\n" + "</html>";
          }
      

    @GetMapping(value="/callbackfoo", produces = MediaType.IMAGE_PNG_VALUE)
    @ResponseBody byte[] qrCodeCallback(@PathParam("code") String code, @PathParam("state") String state) throws Exception {
        if (pkceVerifier == null) {
            throw new Exception("pkceVerifier is null");
        }
        if (nonce == null) {
            throw new Exception("nonce is null");
        }
        logger.info("callback code: %s state: %s verifier: %s nonce: %s", code, state, pkceVerifier.getValue(), nonce.getValue());
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<String, String> map = Map.of("code", code, "state", state, "verifier", pkceVerifier.getValue(), "nonce", nonce.getValue());
        String jsonData = new ObjectMapper().writeValueAsString(map);
        BitMatrix bitMatrix = qrCodeWriter.encode(jsonData, BarcodeFormat.QR_CODE, 200, 200);

        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        MatrixToImageConfig con = new MatrixToImageConfig( 0xFF000002 , 0xFFFFC041 ) ;

        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream,con);
        byte[] pngData = pngOutputStream.toByteArray();
        String qrcode = Base64.getEncoder().encodeToString(pngData);
        logger.info("QR code: " + qrcode);
        logger.info("QR code data: " + jsonData);

        // AuthorizationCode acode = new AuthorizationCode(code);
        // AuthorizationGrant codeGrant = new AuthorizationCodeGrant(acode, callbackUri, pkceVerifier);
        // ClientID clientId = new ClientID(eudiwConfig.getClientId());

        // // Make the token request
        // TokenRequest request = new TokenRequest(tokenEndpoint, clientId, codeGrant);

        // HTTPResponse response = request.toHTTPRequest().send();
        // logger.info("RESPONSE " + response.getBody());
        // TokenResponse tokenResponse = OIDCTokenResponseParser.parse(response);

        // if (! tokenResponse.indicatesSuccess()) {
        //     // We got an error response...
        //     TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
        // }

        // OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();

        // // Get the ID and access token, the server may also return a refresh token
        // JWT idToken = successResponse.getOIDCTokens().getIDToken();
        // AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
        // RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();

        // logger.info("idToken: %s accessToken: %s refreshToken: %s", idToken, accessToken, refreshToken);

        return pngData;
    }

    @GetMapping(value="/callbackdebug", produces = MediaType.TEXT_HTML_VALUE) 
    String callback(@PathParam("code") String code, @PathParam("state") String state) {
        logger.info("Callback called with code: " + code + " and state: " + state);
        // The obtained authorisation code
        AuthorizationCode authorizationCode = new AuthorizationCode(code);

        // Make the token request, with PKCE
        TokenRequest tokenRequest = new TokenRequest(
            URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl())),
            new ClientID(eudiwConfig.getClientId()),
            new AuthorizationCodeGrant(authorizationCode, callbackUri, pkceVerifier));

        logger.info("Created token request");

        try {
            HTTPRequest tokenHttpRequest = tokenRequest.toHTTPRequest();
            logger.info("send token request to: " + tokenHttpRequest.getURL());
            HTTPResponse httpResponse = tokenHttpRequest.send();

            TokenResponse tokenResponse = TokenResponse.parse(httpResponse);

            if (! tokenResponse.indicatesSuccess()) {
                // The token request failed
                ErrorObject errorObject = tokenResponse.toErrorResponse().getErrorObject();
                throw new RuntimeException(errorObject.toString());
            }

            logger.info("sent token request");
            logger.info("token status code: " + tokenResponse.indicatesSuccess());
            AccessTokenResponse accessToken = tokenResponse.toSuccessResponse();
            String jwt = accessToken.getTokens().getBearerAccessToken().getValue();
            logger.info("token jwt: " + jwt);
            //logger.info("token jwt: " + accessToken.getTokens().getRefreshToken().toString());

            return jwt;
        } catch (Exception e) {
            logger.error("Error: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

}
