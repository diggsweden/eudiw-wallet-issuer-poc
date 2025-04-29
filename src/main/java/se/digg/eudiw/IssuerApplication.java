package se.digg.eudiw;

import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import se.digg.eudiw.model.AuthReturnPayload;
import se.digg.eudiw.model.CustomUserDetails;
import se.digg.eudiw.authentication.SwedenConnectAuthenticationToken;
import se.digg.eudiw.authentication.SwedenConnectPrincipal;
import se.swedenconnect.auth.commons.dto.ClientAuthRequest;
import se.swedenconnect.auth.commons.dto.ClientAuthResponse;
import se.swedenconnect.auth.commons.dto.ClientAuthStatus;
import se.swedenconnect.auth.commons.idtoken.CustomClaim;
import se.swedenconnect.auth.commons.idtoken.DisoUI;
import se.swedenconnect.auth.commons.idtoken.IdProfile;
import se.swedenconnect.auth.commons.idtoken.IdTokenClaims;
import se.swedenconnect.auth.commons.idtoken.SourceID;
import se.swedenconnect.auth.commons.idtoken.SubjAttributeType;
import se.swedenconnect.auth.commons.idtoken.SubjAttributes;

@SpringBootApplication
@RegisterReflectionForBinding(
	{
		ClientAuthRequest.class, 
		ClientAuthResponse.class, 
		ClientAuthStatus.class, 
		CustomClaim.class,
		DisoUI.class,
		IdProfile.class,
		IdTokenClaims.class,
		SourceID.class,
		SubjAttributes.class,
		SubjAttributeType.class,
		AuthReturnPayload.class, 
		CustomUserDetails.class, 
		SwedenConnectAuthenticationToken.class, 
		SwedenConnectPrincipal.class
	}
)
@ComponentScan
public class IssuerApplication {

 	public static void main(String[] args) {
		SpringApplication.run(IssuerApplication.class, args);
	}
	
}
