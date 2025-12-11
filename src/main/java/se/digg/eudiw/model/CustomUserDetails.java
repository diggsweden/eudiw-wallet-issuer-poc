package se.digg.eudiw.model;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


public class CustomUserDetails implements UserDetails {
  String personalNumber;
  String name;
  String givenName;
  String surname;
  String birthDate;

  public CustomUserDetails() {}

  public CustomUserDetails(String personalNumber, String name, String givenName, String surname,
      String birthDate) {
    this.personalNumber = personalNumber;
    this.name = name;
    this.givenName = givenName;
    this.surname = surname;
    this.birthDate = birthDate;
  }

  public String getPersonalNumber() {
    return personalNumber;
  }

  public String getName() {
    return name;
  }

  public String getGivenName() {
    return givenName;
  }

  public String getSurname() {
    return surname;
  }

  public String getBirthDate() {
    return birthDate;
  }

  public void setPersonalNumber(String personalNumber) {
    this.personalNumber = personalNumber;
  }

  public void setName(String name) {
    this.name = name;
  }

  public void setGivenName(String givenName) {
    this.givenName = givenName;
  }

  public void setSurname(String surname) {
    this.surname = surname;
  }

  public void setBirthDate(String birthDate) {
    this.birthDate = birthDate;
  }

  @Override
  public String getPassword() {
    return "nopassword";
  }


  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority("USER"));
  }

  @Override
  public String getUsername() {
    return "swedenconnectuser";
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((personalNumber == null) ? 0 : personalNumber.hashCode());
    result = prime * result + ((name == null) ? 0 : name.hashCode());
    result = prime * result + ((givenName == null) ? 0 : givenName.hashCode());
    result = prime * result + ((surname == null) ? 0 : surname.hashCode());
    result = prime * result + ((birthDate == null) ? 0 : birthDate.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    CustomUserDetails other = (CustomUserDetails) obj;
    if (personalNumber == null) {
      if (other.personalNumber != null)
        return false;
    } else if (!personalNumber.equals(other.personalNumber))
      return false;
    if (name == null) {
      if (other.name != null)
        return false;
    } else if (!name.equals(other.name))
      return false;
    if (givenName == null) {
      if (other.givenName != null)
        return false;
    } else if (!givenName.equals(other.givenName))
      return false;
    if (surname == null) {
      if (other.surname != null)
        return false;
    } else if (!surname.equals(other.surname))
      return false;
    if (birthDate == null) {
      if (other.birthDate != null)
        return false;
    } else if (!birthDate.equals(other.birthDate))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "CustomUserDetails [personalNumber=" + personalNumber + ", name=" + name + ", givenName="
        + givenName
        + ", surname=" + surname + ", birthDate=" + birthDate + "]";
  }


}


