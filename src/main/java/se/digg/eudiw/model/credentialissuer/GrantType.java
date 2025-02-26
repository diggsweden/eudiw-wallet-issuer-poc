package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public enum GrantType {
    @JsonProperty("authorization_code")
    AUTHORIZATION_CODE,
    @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    PRE_AUTHORIZED_CODE;
}
