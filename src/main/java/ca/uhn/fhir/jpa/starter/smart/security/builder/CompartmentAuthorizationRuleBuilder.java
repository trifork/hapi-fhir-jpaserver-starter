package ca.uhn.fhir.jpa.starter.smart.security.builder;

import ca.uhn.fhir.jpa.starter.smart.model.SmartClinicalScope;
import ca.uhn.fhir.rest.server.exceptions.NotImplementedOperationException;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRuleBuilderRuleOp;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import org.hl7.fhir.exceptions.FHIRException;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.instance.model.api.IIdType;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.ResourceFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;

@ConditionalOnProperty(prefix = "hapi.fhir", name = "smart_enabled", havingValue = "true")
@Component
public class CompartmentAuthorizationRuleBuilder extends SmartAuthorizationRuleBuilder {

	@Override
	public List<IAuthRule> buildRules(String launchCtx, SmartClinicalScope smartClinicalScope) {
		IAuthRuleBuilder rules = new RuleBuilder();

		if (launchCtx == null || launchCtx.isEmpty()) {
			rules.denyAll("Deny ALL "+smartClinicalScope.getCompartment()+" requests if no launch context is given!");
		} else{
			IIdType resourceId = new IdType(super.getCompartmentResource(smartClinicalScope.getCompartment()), launchCtx);
			filterToResourceScope(resourceId, smartClinicalScope, rules);
		}
		return rules.build();
	}


	protected void filterToResourceScope(IIdType resourceId, SmartClinicalScope smartClinicalScope, IAuthRuleBuilder rules) {
		switch (smartClinicalScope.getOperation()) {
		case ALL: {
			applyResourceScopeClassifier(rules.allow().read(), resourceId, smartClinicalScope);
			applyResourceScopeClassifier(rules.allow().write(), resourceId, smartClinicalScope);
			applyResourceScopeClassifier(rules.allow().delete(), resourceId, smartClinicalScope);
			// resource operations (type or instance level) may read, alter or delete data, should restrict to "*" scope
			applyResourceScopeOperationClassifier(rules, resourceId, smartClinicalScope);
			checkAddPatientEverythingRule(rules, resourceId, smartClinicalScope);
			break;
		}
		case READ:
			applyResourceScopeClassifier(rules.allow().read(), resourceId, smartClinicalScope);
			checkAddPatientEverythingRule(rules, resourceId, smartClinicalScope);
			break;
		case WRITE:
			applyResourceScopeClassifier(rules.allow().write(), resourceId, smartClinicalScope);
			applyResourceScopeClassifier(rules.allow().create(), resourceId, smartClinicalScope);
			applyResourceScopeClassifier(rules.allow().delete(), resourceId, smartClinicalScope);
			break;
		default:
			throw new NotImplementedOperationException("Scope operation " + smartClinicalScope.getOperation().getOperation() + " not supported.");
		}
	}

	protected void checkAddPatientEverythingRule(IAuthRuleBuilder rules, IIdType idType, SmartClinicalScope smartClinicalScope) {
		// if we have patient/*.read or patient/*.* - punch in a patient$everything rule
		if (smartClinicalScope.getResource().equalsIgnoreCase("*") && "Patient".equals(getCompartmentResource(smartClinicalScope.getCompartment()))) {
			rules.allow().operation().named("$everything").onInstance(idType).andAllowAllResponses();
		}
	}

	protected void applyResourceScopeClassifier(IAuthRuleBuilderRuleOp ruleOp, IIdType resourceId, SmartClinicalScope smartClinicalScope) {
		if (smartClinicalScope.getResource().equalsIgnoreCase("*")) {
			ruleOp.allResources().inCompartment(super.getCompartmentResource(smartClinicalScope.getCompartment()), resourceId).andThen();
		} else {
			Class<? extends IBaseResource> resourceType;
			try {
				resourceType = ResourceFactory.createResource(smartClinicalScope.getResource()).getClass();
				ruleOp.resourcesOfType(resourceType).inCompartment(super.getCompartmentResource(smartClinicalScope.getCompartment()), resourceId).andThen();
			} catch (FHIRException e) {
				throw new NotImplementedOperationException("Scope resource " + smartClinicalScope.getResource() + " not supported.");
			}
		}
	}

	protected void applyResourceScopeOperationClassifier(IAuthRuleBuilder rules, IIdType idType, SmartClinicalScope smartClinicalScope) {
		if (smartClinicalScope.getResource().equalsIgnoreCase(super.getCompartmentResource(smartClinicalScope.getCompartment()))) {
			rules.allow().operation().withAnyName().onInstance(idType).andAllowAllResponses();
		}
	}


}
