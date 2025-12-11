package se.swedenconnect.auth.commons.idtoken;

/**
 * Enumeration of the attribute names used in ID tokens. ID tokens can only contain attributes with
 * a name that appear in this enumeration.
 */
public enum SubjAttributeType {

  /** Swedish personnummer */
  personalNumber,
  /** Display name */
  name,
  /** Given name */
  givenName,
  /** Surname */
  surname,
  /** Swedish coordination number (Samordningsnummer) */
  coordinationNumber,
  /** eIDAS provisional ID added by the Swedish eIDAS Connector */
  prid,
  /** Persistence class (A, B or C) of the prid value */
  pridPersistence,
  /** eIDAS person identifier as it was provided by the eID country eIDAS proxy service */
  personIdentifier,
  /** Personal number binding as specified by Sweden Connect technical framework */
  personalNumberBinding,
  /** Organization number */
  orgNumber,
  /**
   * Organization affiliation (id@orgnumber format) as specified by Sweden Connect technical
   * framework
   */
  orgAffiliation,
  /** Organization name */
  orgName,
  /** Organization unit name */
  orgUnit,
  /** User certificate */
  userCertificate,
  /** User signature value */
  userSignature,
  /** eID device IP number */
  deviceIp,
  /** Authentication evidence data */
  authnEvidence,
  /** Country */
  country,
  /** Birth name */
  birthName,
  /** Place of birth */
  placeOfbirth,
  /** Age at the time of authentication */
  age,
  /** Birthdate */
  birthDate;
}
