package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PreAuthorizationCodeGrant implements Grant {
    @JsonProperty("pre-authorized_code")
    String preAuthorizedCode;
    String authorizationServer;
    TxCodeType txCode;

    public PreAuthorizationCodeGrant(String preAuthorizedCode, String authorizationServer, TxCodeType txCode) {
        this.preAuthorizedCode = preAuthorizedCode;
        this.authorizationServer = authorizationServer;
        this.txCode = txCode;
    }

    public String getPreAuthorizedCode() {
        return preAuthorizedCode;
    }

    public void setPreAuthorizedCode(String preAuthorizedCode) {
        this.preAuthorizedCode = preAuthorizedCode;
    }

    public String getAuthorizationServer() {
        return authorizationServer;
    }

    public void setAuthorizationServer(String authorizationServer) {
        this.authorizationServer = authorizationServer;
    }

    public TxCodeType getTxCode() {
        return txCode;
    }

    public void setTxCode(TxCodeType txCode) {
        this.txCode = txCode;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        PreAuthorizationCodeGrant that = (PreAuthorizationCodeGrant) o;
        return Objects.equals(preAuthorizedCode, that.preAuthorizedCode) && Objects.equals(authorizationServer, that.authorizationServer) && Objects.equals(txCode, that.txCode);
    }

    @Override
    public int hashCode() {
        return Objects.hash(preAuthorizedCode, authorizationServer, txCode);
    }

    @Override
    public String toString() {
        return "PreAuthorizationCodeGrant{" +
                "preAuthorizedCode='" + preAuthorizedCode + '\'' +
                ", authorizationServer='" + authorizationServer + '\'' +
                ", txCode=" + txCode +
                '}';
    }
}
