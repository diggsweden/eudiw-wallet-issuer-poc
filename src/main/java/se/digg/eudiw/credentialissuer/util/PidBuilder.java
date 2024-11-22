package se.digg.eudiw.credentialissuer.util;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import se.digg.eudiw.auth.config.SignerConfig;
import se.digg.eudiw.credentialissuer.model.SelectiveDisclosure;

public class PidBuilder {
    List<SelectiveDisclosure> selectiveDisclosures = new ArrayList<SelectiveDisclosure>();
	Map<String, Object> payload = new HashMap<String, Object>();
    Calendar issCalendar;
    //RSAKey rsaJWK;
    //RSAKey rsaPublicJWK;
    private final JWK publicJWK;
    private final String kid;
    private final JWSSigner signer;

    SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd");

    public PidBuilder(String iss, SignerConfig signerConfig) {
        Date now = new Date();
        issCalendar = Calendar.getInstance();
        issCalendar.setTime(now);    
        payload.put("iss", iss);
        payload.put("iat", now);
        payload.put("nbf", now);
        this.signer = signerConfig.getSigner();
        publicJWK = signerConfig.getPublicJwk().toPublicJWK();
        kid = signerConfig.getPublicJwk().getKeyID();
    }

    public PidBuilder withExp(int hours) {
        Calendar expCalendar = Calendar.getInstance();
        expCalendar.setTime(issCalendar.getTime());
        expCalendar.add(Calendar.HOUR_OF_DAY, hours);
        payload.put("exp", expCalendar.getTime());
        return this;
    }

    public PidBuilder withVcType(String type) {
        payload.put("vct", type);
        return this;
    }

    public PidBuilder with(String key, Object value) {
        payload.put(key, value);
        return this;
    }

    public PidBuilder with(String key, boolean value) {
        payload.put(key, Boolean.valueOf(value));
        return this;
    }

    public PidBuilder with(String key, Date value) {
        payload.put("birthdate", dateFormatter.format(value));
        return this;
    }

    public PidBuilder withGivenName(String givenName) {
        payload.put("given_name", givenName);
        return this;
    }

    public PidBuilder withFamilyName(String familyName) {
        payload.put("family_name", familyName);
        return this;
    }

    public PidBuilder withEmail(String email) {
        payload.put("email", email);
        return this;
    }

    public PidBuilder withPhoneNumber(String phoneNumber) {
        payload.put("phone_number", phoneNumber);
        return this;
    }

    public PidBuilder withAddress(String streetAddress, String locality, String region, String country) {
        HashMap<String, String> address = new HashMap<String, String>();
        if (streetAddress != null) address.put("street_address", streetAddress);
        if (locality != null) address.put("locality", locality);
        if (region != null) address.put("region", region);
        if (country != null) address.put("country", country);

        payload.put("address", address);
        return this;
    }

    public PidBuilder withCnf(Map<String, String> cnf) {
        payload.put("cnf", cnf);
        return this;
    }

    public PidBuilder withBirthDate(Date birthDate) {
        String pattern = "yyyy-MM-dd";
        SimpleDateFormat df = new SimpleDateFormat(pattern);
        payload.put("birthdate", df.format(birthDate));
        return this;
    }

    public PidBuilder withIsOver18(boolean isOver18) {
        payload.put("is_over_18", Boolean.valueOf(isOver18));
        return this;
    }

    public PidBuilder withIsOver21(boolean isOver21) {
        payload.put("is_over_21", Boolean.valueOf(isOver21));
        return this;
    }

    public PidBuilder withIsOver65(boolean isOver65) {
        payload.put("is_over_65", Boolean.valueOf(isOver65));
        return this;
    }

    public PidBuilder addSelectiveDisclosure(String name, Object value) {
        selectiveDisclosures.add(new SelectiveDisclosure(name, value));
        return this;
    }

    public String build() {
        StringBuffer sb = new StringBuffer();

        payload.put("_sd", selectiveDisclosures.stream().map(sd -> sd.hash()).collect(Collectors.toList()));

        JWSObject jwsObject = new JWSObject(
            new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(kid)
                .jwk(publicJWK)
                .type(new JOSEObjectType("vc+sd-jwt"))
            .build(),
            new Payload(payload)
        );

        // We need a 256-bit key for HS256 which must be pre-shared
        byte[] sharedKey = new byte[32];
        new SecureRandom().nextBytes(sharedKey);

        try {
            //signer = new RSASSASigner(rsaJWK);
            jwsObject.sign(signer);
            sb.append(jwsObject.serialize());
            sb.append("~");
            
            selectiveDisclosures.stream().forEach(sd -> {
                sb.append(sd.disclosure());
                sb.append("~");
            });
        } catch (Exception e) {
            // TODO: logger 
            throw new RuntimeException(e);
        }
        
        return sb.toString();
    }


}