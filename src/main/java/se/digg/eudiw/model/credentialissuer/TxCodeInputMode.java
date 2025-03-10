package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public enum TxCodeInputMode {
    @JsonProperty("numeric")
    NUMERIC,
    @JsonProperty("text")
    TEXT;
}
