package ca.uhn.fhir.jpa.starter.smart.security.interceptor;

import ca.uhn.fhir.jpa.starter.smart.exception.InvalidClinicalScopeException;
import ca.uhn.fhir.jpa.starter.smart.exception.InvalidSmartOperationException;
import ca.uhn.fhir.jpa.starter.smart.model.SmartClinicalScope;
import ca.uhn.fhir.jpa.starter.smart.model.SmartOperationEnum;
import ca.uhn.fhir.jpa.starter.smart.security.builder.SmartAuthorizationRuleBuilder;
import ca.uhn.fhir.jpa.starter.smart.util.JwtUtility;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizedList;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.SearchNarrowingInterceptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ca.uhn.fhir.jpa.starter.smart.util.JwtUtility.getSmartScopes;


@ConditionalOnProperty(prefix = "hapi.fhir", name = "smart_enabled", havingValue = "true")
@Component
public class SmartSearchNarrowingInterceptor extends SearchNarrowingInterceptor {

	private final JwtDecoder jwtDecoder;


	public SmartSearchNarrowingInterceptor(JwtDecoder jwtDecoder) {
		this.jwtDecoder = jwtDecoder;
	}


	@Override
	protected AuthorizedList buildAuthorizedList(RequestDetails theRequestDetails) {
		Jwt token = JwtUtility.getJwtToken(jwtDecoder, theRequestDetails);

		AuthorizedList authorizedList = new AuthorizedList();

		if (token == null) {
			return authorizedList;
		}

		try{
			Set<SmartClinicalScope> scopes = getSmartScopes(token);
			Map<String, Object> claims = token.getClaims();

			for (SmartClinicalScope scope : scopes) {
				String compartmentName = scope.getCompartment();
				SmartOperationEnum operationEnum = scope.getOperation();
				String id = (String) claims.get(compartmentName);
				if (compartmentName != null && !compartmentName.isEmpty() &&
					(operationEnum.equals(SmartOperationEnum.ALL) || operationEnum.equals(SmartOperationEnum.READ)) ) {
					authorizedList.addCompartment(String.format("%s/%s", compartmentName, id));
				}
			}
		} catch (InvalidClinicalScopeException | InvalidSmartOperationException e) {
			return authorizedList;
		}

		return authorizedList;
	}
}
