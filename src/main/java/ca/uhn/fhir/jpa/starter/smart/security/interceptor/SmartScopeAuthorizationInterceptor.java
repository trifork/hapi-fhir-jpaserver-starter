package ca.uhn.fhir.jpa.starter.smart.security.interceptor;

import ca.uhn.fhir.jpa.starter.smart.exception.InvalidClinicalScopeException;
import ca.uhn.fhir.jpa.starter.smart.exception.InvalidSmartOperationException;
import ca.uhn.fhir.jpa.starter.smart.model.SmartClinicalScope;
import ca.uhn.fhir.jpa.starter.smart.security.builder.SmartAuthorizationRuleBuilder;
import ca.uhn.fhir.jpa.starter.smart.util.JwtUtility;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.*;
import org.springframework.beans.factory.annotation.Value;
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

	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(SmartScopeAuthorizationInterceptor.class);

	private final List<SmartAuthorizationRuleBuilder> ruleBuilders;
	public static final String RULE_DENY_ALL_UNKNOWN_REQUESTS = "Deny all requests that do not match any pre-defined rules";

	private final JwtDecoder jwtDecoder;

	@Value("${hapi.fhir.smart_admin_group_enabled}")
	private boolean smartAdminAccessEnabled;

	@Value("${hapi.fhir.smart_admin_group_claim}")
	private String smartAdminGroupClaim;

	@Value("${smart.allowed_readonly_resources}")
	private List<String> allowedReadOnlyResources;

	public SmartScopeAuthorizationInterceptor(List<SmartAuthorizationRuleBuilder> ruleBuilders, JwtDecoder jwtDecoder) {
		this.setFlags(AuthorizationFlagsEnum.DO_NOT_PROACTIVELY_BLOCK_COMPARTMENT_READ_ACCESS);
		this.ruleBuilders = ruleBuilders;
		this.jwtDecoder = jwtDecoder;
	}

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		Jwt token = JwtUtility.getJwtToken(jwtDecoder, theRequestDetails);
		IAuthRuleBuilder authRuleBuilder = new RuleBuilder();

		// allow metadata
		authRuleBuilder.allow().metadata();

		List<IAuthRule> ruleList = new ArrayList<>();

		if (token == null) {
			return authRuleBuilder.build();
		}

		// Check if admin user
		if( smartAdminAccessEnabled && smartAdminGroupClaim != null ) {

			List<String> groups = token.getClaimAsStringList("group");
			if( groups != null ) {
				for( String group : groups ) {
					if ( smartAdminGroupClaim.equals(group) ) {
						authRuleBuilder.allowAll();
						//can short-circuit here since we are returning a rule with unrestricted access
						return authRuleBuilder.build();
					}
				}
			}
		}

		try {
			Set<SmartClinicalScope> scopes = getSmartScopes(token);
			Map<String, Object> claims = token.getClaims();
			for (SmartClinicalScope scope : scopes) {
				String compartmentName = scope.getCompartment();
				if (compartmentName != null && !compartmentName.isEmpty()) {

					// Since we'll be using different builder(s) to create the SMART scope rules
					// we need to add the rules created to this point to the return list and reset our builder
					// so we don't the same rules to the list twice.
					ruleList.addAll(authRuleBuilder.build());
					authRuleBuilder = new RuleBuilder(); // reset so we don't re-add the rules to the list twice

					// create rules for all the SMART scopes in the token
					ruleBuilders.stream().filter(smartAuthorizationRuleBuilder -> smartAuthorizationRuleBuilder.hasRegisteredResource(compartmentName)).forEach(smartAuthorizationRuleBuilder -> {

						String launchCtxName = smartAuthorizationRuleBuilder.getLaunchCtxName(compartmentName);
						String launchCtx = (String) claims.get(launchCtxName);

						ruleList.addAll(smartAuthorizationRuleBuilder.buildRules(launchCtx, scope));

						// removed code
						/*if (theRequestDetails.getRequestType().equals(RequestTypeEnum.GET) && theRequestDetails.getId() == null) {
							if (scope.getResource().equalsIgnoreCase("*")) {
								ruleList.addAll(authRuleBuilder.allow().read().allResources().withAnyId().build());
							} else {
								ruleList.addAll(authRuleBuilder.allow().read().resourcesOfType(scope.getResource()).withAnyId().build());
							}
						} else {
							ruleList.addAll(smartAuthorizationRuleBuilder.buildRules(launchCtx, scope));
						}*/
					});
				}
			}

			// add supplemental rules
			for (String resourceName : allowedReadOnlyResources) {
				authRuleBuilder.allow().read().resourcesOfType(resourceName).withAnyId();
			}

		} catch (InvalidClinicalScopeException | InvalidSmartOperationException e) {
			ourLog.error("caught e->{}", e, e);
			// return a deny all rule
			return new RuleBuilder().denyAll(e.getMessage()).build();
		}

		// add a final deny all to catch anything that falls through
		authRuleBuilder.denyAll(RULE_DENY_ALL_UNKNOWN_REQUESTS);
		ruleList.addAll(authRuleBuilder.build());

		/*for (IAuthRule rule : ruleList) {
			String ruleStr = rule.toString();
			ourLog.debug("  our list ruleStr->{}", ruleStr);
		}*/


		return ruleList;
	}

}