package se.digg.eudiw.controllers;

import com.google.zxing.WriterException;
import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import se.digg.eudiw.model.CredentialIssuanceRequest;
import se.digg.eudiw.model.CredentialIssuanceStatus;
import se.digg.eudiw.model.ItbException;
import se.digg.eudiw.model.ItpErrorResponse;
import se.digg.eudiw.service.CredentialOfferService;
import se.digg.eudiw.service.EwcItbService;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

@Controller
public class EwcItbController {

  Logger logger = LoggerFactory.getLogger(EwcItbController.class);

  private final CredentialOfferService credentialOfferService;
  private final EwcItbService ewcItbService;

  public EwcItbController(
      CredentialOfferService credentialOfferService,
      EwcItbService ewcItbService) {
    this.credentialOfferService = credentialOfferService;

    this.ewcItbService = ewcItbService;

    logger.info("PreAuthController created");

  }

  @GetMapping("/credentialIssuanceRequest")
  ResponseEntity<CredentialIssuanceRequest> credentialOffer(@RequestParam String sessionId,
      @RequestParam List<String> credentialType) {
    try {
      CredentialIssuanceRequest credentialIssuanceRequest =
          ewcItbService.initAuthFlow(sessionId, credentialType);
      return ResponseEntity.ok().body(credentialIssuanceRequest);
    } catch (URISyntaxException | ParseException | JOSEException | IOException
        | WriterException e) {
      throw new ItbException("fail",
          "An internal server error occurred in issuer while processing the request", sessionId);
    }
  }


  @GetMapping("/issueStatus")
  ResponseEntity<CredentialIssuanceStatus> issueStatus(@RequestParam String sessionId) {
    String credentialOfferFormId = EwcItbService.calculateOfferId(sessionId);

    String credentialOfferId = credentialOfferService.pendingEwcItpIssuance(credentialOfferFormId);
    if (credentialOfferId == null) {
      return ResponseEntity.ok().body(new CredentialIssuanceStatus("fail",
          "no issuance session found",
          sessionId));
    }

    String status = credentialOfferService.pendingEwcItpIssuance(credentialOfferId);

    if (status == null) {
      return ResponseEntity.ok().body(new CredentialIssuanceStatus("fail",
          "no issuance session found",
          sessionId));
    }

    return ResponseEntity.ok().body(new CredentialIssuanceStatus(status, "ok", sessionId));
  }

  @GetMapping("/qr")
  ModelAndView qr(Model model) {
    String sessionId = UUID.randomUUID().toString();
    List<String> credentialType =
        List.of("eu.europa.ec.eudi.pid_vc_sd_jwt", "eu.europa.ec.eudi.pid_mdoc");
    return qrModelAndView(model, sessionId, credentialType);
  }

  @GetMapping("/qr-sdjwt")
  ModelAndView qrSdJwtVc(Model model) {
    String sessionId = UUID.randomUUID().toString();
    List<String> credentialType =
        List.of("eu.europa.ec.eudi.pid_vc_sd_jwt");
    return qrModelAndView(model, sessionId, credentialType);
  }

  @GetMapping("/qr-mdoc")
  ModelAndView qrMsoMDoc(Model model) {
    String sessionId = UUID.randomUUID().toString();
    List<String> credentialType =
        List.of("eu.europa.ec.eudi.pid_mdoc");
    return qrModelAndView(model, sessionId, credentialType);
  }

  private ModelAndView qrModelAndView(Model model, String sessionId, List<String> credentialType) {
    try {
      CredentialIssuanceRequest credentialIssuanceRequest =
          ewcItbService.initAuthFlow(sessionId, credentialType);
      model.addAttribute("qrCode", credentialIssuanceRequest.qr());
      return new ModelAndView("qr", model.asMap());
    } catch (URISyntaxException | ParseException | JOSEException | IOException
        | WriterException e) {
      throw new RuntimeException("Error generating QR code");
    }
  }

  @ExceptionHandler({ItbException.class})
  public ResponseEntity<ItpErrorResponse> handleItbException(Exception ex) {
    logger.info("Error in EWC ITB controller", ex);
    ItbException itbException = (ItbException) ex;
    ItpErrorResponse errorResponse = new ItpErrorResponse(
        itbException.getStatus(),
        itbException.getReason(),
        itbException.getSessionId());
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
  }

  @ExceptionHandler({Exception.class})
  public ResponseEntity<String> handleException(Exception ex) {
    logger.info("Error in EWC ITB controller", ex);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
  }

}
