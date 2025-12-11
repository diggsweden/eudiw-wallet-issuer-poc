package se.swedenconnect.auth.commons.idtoken;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data class that holds the identifiers of the source requests and responses from the upstream
 * IdP/OP
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SourceID {

  /** An ID of the request sent to the identity provider */
  String request;
  /** The ID of the identity evidence (toke or assertion) provided by the identity provider */
  String token;
}
