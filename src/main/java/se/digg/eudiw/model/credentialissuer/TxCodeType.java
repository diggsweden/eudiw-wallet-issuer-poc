package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TxCodeType {
    private TxCodeInputMode inputMode;
    private int length;
    private String description;

    public TxCodeType() {
    }

    public TxCodeType(TxCodeInputMode inputMode, int length, String description) {
        this.inputMode = inputMode;
        this.length = length;
        this.description = description;
    }

    public TxCodeInputMode getInputMode() {
        return inputMode;
    }

    public void setInputMode(TxCodeInputMode inputMode) {
        this.inputMode = inputMode;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        TxCodeType that = (TxCodeType) o;
        return length == that.length && inputMode == that.inputMode && Objects.equals(description, that.description);
    }

    @Override
    public int hashCode() {
        return Objects.hash(inputMode, length, description);
    }

    @Override
    public String toString() {
        return "TxCodeType{" +
                "inputMode=" + inputMode +
                ", length=" + length +
                ", description='" + description + '\'' +
                '}';
    }
}
