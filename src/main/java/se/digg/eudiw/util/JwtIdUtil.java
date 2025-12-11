package se.digg.eudiw.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.config.SignerConfig;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

@Component
public class JwtIdUtil {


  private static final Logger logger = LoggerFactory.getLogger(JwtIdUtil.class);
  private final EudiwConfig eudiwConfig;
  private final SignerConfig signer;
  private final Random rnd;

  public JwtIdUtil(EudiwConfig eudiwConfig, SignerConfig signer) {
    this.signer = signer;
    this.eudiwConfig = eudiwConfig;
    this.rnd = new Random();
  }

  public String id2jwt(String id) throws JOSEException {
    logger.info("id2jwt: {}", id);
    JWSAlgorithm algorithm = JWSAlgorithm.ES256;
    Date now = new Date();
    Calendar issCalendar = Calendar.getInstance();
    issCalendar.setTime(now);
    Calendar expCalendar = Calendar.getInstance();
    expCalendar.setTime(issCalendar.getTime());
    expCalendar.add(Calendar.MINUTE, 10); // todo config

    JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
    claimsSetBuilder.issuer(eudiwConfig.getIssuer()).subject(eudiwConfig.getIssuer())
        .claim("id", id).jwtID(new BigInteger(128, rnd).toString(16))
        .expirationTime(expCalendar.getTime()).issueTime(issCalendar.getTime());
    SignedJWT jwt =
        new SignedJWT(new JWSHeader.Builder(algorithm).keyID(signer.getPublicJwk().getKeyID()).type(
            JOSEObjectType.JWT).build(), claimsSetBuilder.build());
    jwt.sign(signer.getSigner());

    return jwt.serialize();
  }

  public String jwt2id(String jwt) throws JOSEException, ParseException {
    logger.info("jwt2id: {}", jwt);
    SignedJWT signedJWT = SignedJWT.parse(jwt);
    if (!signedJWT.verify(signer.getJwsVerifier())) {
      throw new JOSEException("Signature verification failed");
    }
    signedJWT.getPayload().toJSONObject().get("id");
    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    return claimsSet.getStringClaim("id");
  }
}
