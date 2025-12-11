package se.digg.eudiw.util.deserializers;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;

import java.io.IOException;

public class CodeVerifierCustomDeserializer extends JsonDeserializer<CodeVerifier> {

  @Override
  public CodeVerifier deserialize(JsonParser jsonParser,
      DeserializationContext deserializationContext) throws IOException, JacksonException {
    ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
    JsonNode node = mapper.readTree(jsonParser);
    if (node.has("value")) {
      String value = node.get("value").asText();
      return new CodeVerifier(value);
    }
    return null;
  }
}
