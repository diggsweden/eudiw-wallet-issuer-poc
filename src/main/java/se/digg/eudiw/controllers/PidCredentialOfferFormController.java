package se.digg.eudiw.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.CredentialOfferFormParam;
import se.digg.eudiw.model.credentialissuer.AuthorizationCodeGrant;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.GrantType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Controller
public class PidCredentialOfferFormController {

    private static final Logger logger = LoggerFactory.getLogger(PidCredentialOfferFormController.class);
    private final EudiwConfig eudiwConfig;

    public PidCredentialOfferFormController(EudiwConfig eudiwConfig) {
        this.eudiwConfig = eudiwConfig;
    }

    @GetMapping("/pid")
    public String pidCredentialOffer(Model model) {
        model.addAttribute("credentialOffer", new CredentialOfferFormParam());
        model.addAttribute("urn:eu.europa.ec.eudi:pid:1", Boolean.FALSE);
        return "pid-credential-offer";
    }

    /*
    openid-credential-offer://credential_offer?credential_offer={
"credential_issuer": "https://issuer.eudiw.dev",
"credential_configuration_ids": ["eu.europa.ec.eudi.pid_jwt_vc_json", "eu.europa.ec.eudi.pid_mdoc"],
"grants": {"authorization_code": {}}}

openid-credential-offer://
credential_offer?credential_offer=
{"credential_issuer": "https://issuer.eudiw.dev",
"credential_configuration_ids": ["eu.europa.ec.eudi.pid_jwt_vc_json", "eu.europa.ec.eudi.pid_mdoc"],
"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
    "pre-authorized_code": "28802d55-f44f-4545-afa7-f0d2c6e4d379",
    "tx_code": {"length": 5, "input_mode": "numeric", "description": "Please provide the one-time code."}
    }}}


     */
    @PostMapping("/pid")
    public String pidCredentialOffer(@ModelAttribute CredentialOfferFormParam credentialOffer, Model model) {

        model.addAttribute("credentialOffer", credentialOffer);

        if (credentialOffer.isPidMsoMdoc() || credentialOffer.isPidSdJwtVc()) {

            if (credentialOffer.isPreAuthCodeFlow()) {
                credentialOffer.setValidationErrors("TODO implementera");
                return "pid-credential-offer";
            }

            String credentialOfferId = UUID.randomUUID().toString();

            QRCodeWriter qrCodeWriter = new QRCodeWriter();

            CredentialOfferParam credentialOfferParam = new CredentialOfferParam(eudiwConfig.getIssuer(), credentialOffer.listOfCredentials());
            credentialOfferParam.setGrants(Map.of(GrantType.AUTHORIZATION_CODE, new AuthorizationCodeGrant()));

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

                model.addAttribute("qrCode", String.format("data:image/jpeg;base64, %s", qrCode));
                model.addAttribute("linkUrl", credOffer);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            } catch (WriterException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }
        else {
            credentialOffer.setValidationErrors("Minst ett pid format måste markeras");
        }

        return "pid-credential-offer";
    }
}
