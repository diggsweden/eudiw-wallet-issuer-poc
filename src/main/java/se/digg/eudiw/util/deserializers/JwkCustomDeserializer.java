package se.digg.eudiw.util.deserializers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.nimbusds.jose.jwk.JWK;

import java.io.IOException;
import java.text.ParseException;

public class JwkCustomDeserializer extends JsonDeserializer<JWK> {

  @Override
  public JWK deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
      throws IOException {
    try {
      String jwkJson = jsonParser.readValueAsTree().toString();
      return JWK.parse(jwkJson);
    } catch (ParseException e) {
      throw new IOException("Failed to parse JWK: " + e.getMessage(), e);
    }
  }
}
