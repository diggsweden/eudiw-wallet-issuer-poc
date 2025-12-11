package se.digg.eudiw.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import se.digg.eudiw.authentication.SwedenConnectPrincipal;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.CredentialOfferDeepLinkAndQrCode;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.GrantType;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;
import se.digg.eudiw.model.credentialissuer.TxCodeInputMode;
import se.digg.eudiw.model.credentialissuer.TxCodeType;
import se.digg.eudiw.util.JwtIdUtil;
import se.swedenconnect.auth.commons.idtoken.SubjAttributes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class CredentialOfferServiceImpl implements CredentialOfferService {


  private static final SecureRandom rng = new SecureRandom();
  private static final Logger logger = LoggerFactory.getLogger(CredentialOfferServiceImpl.class);

  private final RedisOperations<String, CredentialOfferParam> operations;
  private final RedisOperations<String, List<String>> selectedCredentialsRedisOperations;

  private final RedisOperations<String, PendingPreAuthorization> pendingPreAuthorizationRedisOperations;
  private final RedisOperations<String, String> ewcItbPendingIssuanceOperations;

  private final JwtIdUtil jwtIdUtil;
  private final EudiwConfig eudiwConfig;
  private final Random rnd = new Random();


  public CredentialOfferServiceImpl(RedisOperations<String, CredentialOfferParam> operations,
      RedisOperations<String, List<String>> selectedCredentialsRedisOperations,
      RedisOperations<String, PendingPreAuthorization> pendingPreAuthorizationRedisOperations,
      RedisOperations<String, String> ewcItbPendingIssuanceOperations, EudiwConfig eudiwConfig,
      JwtIdUtil jwtIdUtil) {
    this.operations = operations;
    this.selectedCredentialsRedisOperations = selectedCredentialsRedisOperations;
    this.ewcItbPendingIssuanceOperations = ewcItbPendingIssuanceOperations;
    this.eudiwConfig = eudiwConfig;
    this.pendingPreAuthorizationRedisOperations = pendingPreAuthorizationRedisOperations;
    this.jwtIdUtil = jwtIdUtil;
  }

  @Override
  public CredentialOfferParam credentialOffer(String credentialOfferId) {
    // TODO: change back to getAndDelete - temporary fix for android reference implementation wallet
    // app
    CredentialOfferParam result = operations.opsForValue().get(credentialOfferId);

    // dumb solution in order to support pending issuance operations in the EWC ITB
    if (result != null) {
      ewcItbPendingIssuanceOperations.opsForValue().set(
          String.format("status-%s", credentialOfferId), "success",
          eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    }

    return result;
  }

  @Override
  public void store(String credentialOfferId, CredentialOfferParam credentialOffer) {
    operations.opsForValue().set(credentialOfferId, credentialOffer,
        eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
  }

  @Override
  public List<String> selectedCredentials(String selectedCredentialsId) {
    return selectedCredentialsRedisOperations.opsForValue().getAndDelete(selectedCredentialsId);
  }

  @Override
  public void store(String selectedCredentialsId, List<String> selectedCredentials) {
    selectedCredentialsRedisOperations.opsForValue().set(selectedCredentialsId, selectedCredentials,
        eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
  }

  @Override
  public void store(String preAuthCode, PendingPreAuthorization pendingPreAuthorization) {
    pendingPreAuthorizationRedisOperations.opsForValue().set(preAuthCode, pendingPreAuthorization,
        eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
  }

  @Override
  public PendingPreAuthorization pendingPreAuthorization(String preAuthCode) {
    return pendingPreAuthorizationRedisOperations.opsForValue().getAndDelete(preAuthCode);
  }

  @Override
  public String pendingEwcItpIssuance(String credentialOfferId) {
    // dumb solution in order to support pending issuance operations in the EWC ITB
    return ewcItbPendingIssuanceOperations.opsForValue()
        .get(String.format("status-%s", credentialOfferId));
  }



  @Override
  public String createCredentialOffer(CodeVerifier pkceVerifier, String codeParam,
      String state, URI callbackUri)
      throws JOSEException, ParseException, IOException, WriterException {
    logger.info("code: {}", codeParam);
    String credentialOfferFormId = jwtIdUtil.jwt2id(state);
    List<String> selectedCredentials = selectedCredentials(credentialOfferFormId);
    AuthorizationCode code = new AuthorizationCode(codeParam);
    AuthorizationGrant codeGrant = new PreAuthCodeAuthorizationGrant(code, callbackUri,
        pkceVerifier);

    logger.info("codeGrant: {}", codeGrant.toParameters());

    ClientID clientID = new ClientID(eudiwConfig.getClientId());

    CredentialOfferParam credentialOfferParam =
        new CredentialOfferParam(eudiwConfig.getIssuer(), selectedCredentials);
    credentialOfferParam.setGrants(Map.of(GrantType.PRE_AUTHORIZED_CODE,
        new se.digg.eudiw.model.credentialissuer.PreAuthorizationCodeGrant(
            codeParam, eudiwConfig.getAuthHost(),
            new TxCodeType(TxCodeInputMode.NUMERIC, 6, "PIN"))));

    SecurityContext context = SecurityContextHolder.getContext();
    Authentication authentication = context.getAuthentication();
    SwedenConnectPrincipal swedenConnectPrincipal = null;
    Object principal = authentication.getPrincipal();
    if (principal instanceof SwedenConnectPrincipal) {
      swedenConnectPrincipal = (SwedenConnectPrincipal) principal;
    }

    if (swedenConnectPrincipal == null && callbackUri.getPath().startsWith("/callback-ewc-itb")) {
      // horrible hack for test environment
      SubjAttributes s = SubjAttributes.builder()
          .personalNumber("197705232382")
          .birthDate("19770523")
          .country("SE")
          .givenName("Frida")
          .surname("Kranstege").build();
      swedenConnectPrincipal = new SwedenConnectPrincipal(s);
    }

    if (swedenConnectPrincipal == null) {
      throw new RuntimeException("TODO handle not authenticated");
    }

    int number = rnd.nextInt(999999);

    String txCode = String.format("%06d", number);
    PendingPreAuthorization pendingPreAuthorization =
        new PendingPreAuthorization(credentialOfferParam, callbackUri.toString(),
            pkceVerifier, clientID.getValue(), txCode, swedenConnectPrincipal);
    store(code.getValue(), pendingPreAuthorization);

    logger.info("Pending Credential offer: {}", pendingPreAuthorization);

    String credentialOfferId = UUID.randomUUID().toString();
    store(credentialOfferId, credentialOfferParam);


    // dumb solution in order to support pending issuance operations in the EWC ITB
    ewcItbPendingIssuanceOperations.opsForValue().set(
        String.format("status-%s", credentialOfferFormId), credentialOfferId,
        eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    ewcItbPendingIssuanceOperations.opsForValue().set(String.format("status-%s", credentialOfferId),
        "pending", eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);

    return credentialOfferId;
  }

  @Override
  public CredentialOfferDeepLinkAndQrCode credentialOfferDeepLinkAndQrCode(
      String credentialOfferId)
      throws IOException, WriterException {
    String credentialUrl =
        String.format("%s/credential_offer/%s", eudiwConfig.getIssuerBaseUrl(), credentialOfferId);
    String credOffer =
        String.format("openid-credential-offer://credential_offer?credential_offer_uri=%s",
            URLEncoder.encode(credentialUrl, StandardCharsets.UTF_8));

    logger.info("Creating QR code for credential offer: {}", credOffer);
    QRCodeWriter qrCodeWriter = new QRCodeWriter();

    BitMatrix bitMatrix = qrCodeWriter.encode(credOffer, BarcodeFormat.QR_CODE, 300, 300);

    ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
    MatrixToImageConfig con = new MatrixToImageConfig();

    MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream, con);
    byte[] pngData = pngOutputStream.toByteArray();

    return new CredentialOfferDeepLinkAndQrCode(credOffer,
        Base64.getEncoder().encodeToString(pngData));
  }

  protected static class PreAuthCodeAuthorizationGrant extends AuthorizationGrant {
    private final AuthorizationCode code;
    private final URI redirectURI;
    private final CodeVerifier pkceVerifier;
    private static final com.nimbusds.oauth2.sdk.GrantType GRANT_TYPE =
        new com.nimbusds.oauth2.sdk.GrantType(
            "urn:ietf:params:oauth:grant-type:pre-authorized_code");

    PreAuthCodeAuthorizationGrant(AuthorizationCode code, URI redirectURI,
        CodeVerifier pkceVerifier) {
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
