package ca.uhn.fhir.jpa.starter.smart.util;

import ca.uhn.fhir.jpa.starter.smart.model.SmartClinicalScope;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.util.HashSet;
import java.util.Set;

public class JwtUtility {

	private JwtUtility(){

	}

	public static Jwt getJwtToken(JwtDecoder decoder, RequestDetails requestDetails){
		String authHeader = requestDetails.getHeader("Authorization");
		if (authHeader == null || authHeader.isEmpty()) {
			return null;
		}
		try{
			return decoder.decode(authHeader.replace("Bearer ", ""));
		} catch (JwtValidationException e){
			throw new AuthenticationException(e.getMessage());
		}
	}

	public static Set<SmartClinicalScope> getSmartScopes(Jwt token) {
		try{
			Set<SmartClinicalScope> smartClinicalScopes = new HashSet<>();
			String[] scopes = token.getClaimAsString("scope").split(" ");

			for (String scope : scopes) {
				SmartClinicalScope smartScope = SmartClinicalScope.createIfValidSmartClinicalScope(scope);
				if( smartScope != null ) {
					smartClinicalScopes.add(smartScope);
				}
			}
			return smartClinicalScopes;
		} catch (NullPointerException e){
			throw new ForbiddenOperationException("No scope provided");
		}
	}

}
