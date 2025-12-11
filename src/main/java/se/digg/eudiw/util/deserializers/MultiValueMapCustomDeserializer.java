package se.digg.eudiw.util.deserializers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

public class MultiValueMapCustomDeserializer
    extends JsonDeserializer<MultiValueMap<String, String>> {

  @Override
  public MultiValueMap<String, String> deserialize(JsonParser jp, DeserializationContext ctxt)
      throws IOException, JsonProcessingException {

    MultiValueMap<String, String> result = new LinkedMultiValueMap<>();
    JsonNode node = jp.getCodec().readTree(jp);

    if (node.isObject()) {
      Iterator<Entry<String, JsonNode>> fields = node.fields();

      while (fields.hasNext()) {
        Entry<String, JsonNode> entry = fields.next();
        String key = entry.getKey();
        JsonNode valueNode = entry.getValue();

        if (valueNode.isArray()) {
          List<String> values = new ArrayList<>();
          for (JsonNode item : valueNode) {
            values.add(item.asText());
          }
          result.put(key, values);
        } else {
          // If not an array, treat as a single value
          result.add(key, valueNode.asText());
        }
      }
    }

    return result;
  }
}
