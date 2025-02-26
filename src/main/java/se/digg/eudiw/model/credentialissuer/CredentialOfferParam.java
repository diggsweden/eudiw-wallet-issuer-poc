package se.digg.eudiw.model.credentialissuer;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;


@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialOfferParam {

    String credentialIssuer;
    List<String> credentialConfigurationIds;
    Map<GrantType, Grant> grants;

    public CredentialOfferParam(String credentialIssuer, List<String> credentialConfigurationIds) {
        this.credentialIssuer = credentialIssuer;
        this.credentialConfigurationIds = credentialConfigurationIds;
        this.grants = new HashMap<>();
    }

    public String getCredentialIssuer() {
        return credentialIssuer;
    }

    public void setCredentialIssuer(String credentialIssuer) {
        this.credentialIssuer = credentialIssuer;
    }

    public List<String> getCredentialConfigurationIds() {
        return credentialConfigurationIds;
    }   

    public void setCredentialConfigurationIds(List<String> credentialConfigurationIds) {
        this.credentialConfigurationIds = credentialConfigurationIds;
    }

    public Map<GrantType, Grant> getGrants() {
        return grants;
    }

    public void setGrants(Map<GrantType, Grant> grants) {
        this.grants = grants;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((credentialIssuer == null) ? 0 : credentialIssuer.hashCode());
        result = prime * result + ((credentialConfigurationIds == null) ? 0 : credentialConfigurationIds.hashCode());
        result = prime * result + ((grants == null) ? 0 : grants.hashCode());
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
        CredentialOfferParam other = (CredentialOfferParam) obj;
        if (credentialIssuer == null) {
            if (other.credentialIssuer != null)
                return false;
        } else if (!credentialIssuer.equals(other.credentialIssuer))
            return false;
        if (credentialConfigurationIds == null) {
            if (other.credentialConfigurationIds != null)
                return false;
        } else if (!credentialConfigurationIds.equals(other.credentialConfigurationIds))
            return false;
        if (grants == null) {
            if (other.grants != null)
                return false;
        } else if (!grants.equals(other.grants))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "CredentialOfferParam [credentialIssuer=" + credentialIssuer + ", credentials=" + credentialConfigurationIds
                + ", grants=" + grants + "]";
    }

}
