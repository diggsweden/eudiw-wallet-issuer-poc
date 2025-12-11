package se.digg.eudiw.util.deserializers;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import se.digg.eudiw.model.credentialissuer.AuthorizationCodeGrant;
import se.digg.eudiw.model.credentialissuer.Grant;
import se.digg.eudiw.model.credentialissuer.PreAuthorizationCodeGrant;

import java.io.IOException;

public class GrantCustomDeserializer extends JsonDeserializer<Grant> {

  @Override
  public Grant deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
      throws IOException, JacksonException {
    ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
    JsonNode node = mapper.readTree(jsonParser);

    if (node.has("pre-authorized_code")) {
      return mapper.treeToValue(node, PreAuthorizationCodeGrant.class);
    }
    return mapper.treeToValue(node, AuthorizationCodeGrant.class);
  }
}
