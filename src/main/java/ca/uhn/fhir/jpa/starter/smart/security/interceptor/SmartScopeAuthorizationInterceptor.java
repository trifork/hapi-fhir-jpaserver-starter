package ca.uhn.fhir.jpa.starter.smart.security.interceptor;

import ca.uhn.fhir.jpa.starter.smart.exception.InvalidClinicalScopeException;
import ca.uhn.fhir.jpa.starter.smart.exception.InvalidSmartOperationException;
import ca.uhn.fhir.jpa.starter.smart.model.SmartClinicalScope;
import ca.uhn.fhir.jpa.starter.smart.security.builder.SmartAuthorizationRuleBuilder;
import ca.uhn.fhir.jpa.starter.smart.util.JwtUtility;
import ca.uhn.fhir.rest.api.RequestTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.*;
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
public class SmartScopeAuthorizationInterceptor extends AuthorizationInterceptor {

	private final List<SmartAuthorizationRuleBuilder> ruleBuilders;
	public static final String RULE_DENY_ALL_UNKNOWN_REQUESTS = "Deny all requests that do not match any pre-defined rules";

	private final JwtDecoder jwtDecoder;


	public SmartScopeAuthorizationInterceptor(List<SmartAuthorizationRuleBuilder> ruleBuilders, JwtDecoder jwtDecoder) {
		this.setFlags(AuthorizationFlagsEnum.DO_NOT_PROACTIVELY_BLOCK_COMPARTMENT_READ_ACCESS);
		this.ruleBuilders = ruleBuilders;
		this.jwtDecoder = jwtDecoder;
	}

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		Jwt token = JwtUtility.getJwtToken(jwtDecoder, theRequestDetails);
		IAuthRuleBuilder authRuleBuilder = new RuleBuilder();
		List<IAuthRule> ruleList = new ArrayList<>(authRuleBuilder.allow().metadata().build());

		if (token == null) {
			return ruleList;
		}

		try {
			Set<SmartClinicalScope> scopes = getSmartScopes(token);
			Map<String, Object> claims = token.getClaims();
			for (SmartClinicalScope scope : scopes) {
				String compartmentName = scope.getCompartment();
				if (compartmentName != null && !compartmentName.isEmpty()) {
					ruleBuilders.stream().filter(smartAuthorizationRuleBuilder -> smartAuthorizationRuleBuilder.hasRegisteredResource(compartmentName)).forEach(smartAuthorizationRuleBuilder -> {
						String launchCtxName = smartAuthorizationRuleBuilder.getLaunchCtxName(compartmentName);
						String launchCtx = (String) claims.get(launchCtxName);
						if (theRequestDetails.getRequestType().equals(RequestTypeEnum.GET) && theRequestDetails.getId() == null){
							if(scope.getResource().equalsIgnoreCase("*")){
								ruleList.addAll(authRuleBuilder.allow().read().allResources().withAnyId().build());
							} else ruleList.addAll(authRuleBuilder.allow().read().resourcesOfType(scope.getResource()).withAnyId().build());
						} else {
							ruleList.addAll(smartAuthorizationRuleBuilder.buildRules(launchCtx, scope));
						}
					});
				}
			}
			ruleList.addAll(authRuleBuilder.denyAll(RULE_DENY_ALL_UNKNOWN_REQUESTS).build());
		} catch (InvalidClinicalScopeException | InvalidSmartOperationException e) {
			ruleList.addAll(authRuleBuilder.denyAll(e.getMessage()).build());
		}

		return ruleList;
	}


}