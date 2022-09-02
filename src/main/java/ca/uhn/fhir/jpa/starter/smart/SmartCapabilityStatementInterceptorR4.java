package ca.uhn.fhir.jpa.starter.smart;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.hl7.fhir.instance.model.api.IBaseConformance;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.UriType;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementRestComponent;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementRestSecurityComponent;
import org.hl7.fhir.r4.model.CapabilityStatement.RestfulCapabilityMode;
import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;

@Interceptor
public class SmartCapabilityStatementInterceptorR4 {

	private String authorizationEndpoint;
	private String tokenEndpoint;
	private String managementEndpoint;
	private String introspectionEndpoint;
	private String revocationEndpoint;

	public SmartCapabilityStatementInterceptorR4(String authorizationEndpoint, String tokenEndpoint, String managementEndpoint, String introspectionEndpoint, String revocationEndpoint) {
		super();
		this.authorizationEndpoint = authorizationEndpoint;
		this.tokenEndpoint = tokenEndpoint;
		this.managementEndpoint = managementEndpoint;
		this.introspectionEndpoint = introspectionEndpoint;
		this.revocationEndpoint = revocationEndpoint;
	}

	@Hook(Pointcut.SERVER_CAPABILITY_STATEMENT_GENERATED)
	public void customize(IBaseConformance theCapabilityStatement) {

		// Cast to the appropriate version
		CapabilityStatement cs = (CapabilityStatement) theCapabilityStatement;


		// Customize the CapabilityStatement as desired
		// cs.getSoftware().setName("Acme FHIR Server").setVersion("1.0").setReleaseDateElement(new DateTimeType("2021-02-06"));

		CapabilityStatementRestSecurityComponent securityComponent = this.buildSecurityComponent();

		// Get the CapabilityStatementRestComponent for the server if one exists
		List<CapabilityStatementRestComponent> restComponents = cs.getRest();
		CapabilityStatementRestComponent rest = null;
		for (CapabilityStatementRestComponent rc : restComponents) {
			if (rc.getMode().equals(RestfulCapabilityMode.SERVER)) {
				rest = rc;
				break;
			}
		}

		if (rest == null) {
			// Create new rest component
			rest = new CapabilityStatementRestComponent();
			rest.setMode(RestfulCapabilityMode.SERVER);
			rest.setSecurity(securityComponent);
			cs.addRest(rest);
		} else {
			rest.setSecurity(securityComponent);
		}

	}

	private CapabilityStatementRestSecurityComponent buildSecurityComponent() {
		CapabilityStatementRestSecurityComponent securityComponent = new CapabilityStatementRestSecurityComponent();

		// see http://hl7.org/fhir/smart-app-launch/1.0.0/conformance/index.html#example
		// NOTE: this CodeableConcept is included in the in the smart example above, but it fails Touchstone validation
		// and is not required by SMART per: https://chat.fhir.org/#narrow/stream/179170-smart/topic/SMART.20on.20FHIR.20v1.20System.20Links.20Broken
		// CodeableConcept cc = securityComponent.addService();
		// cc.addCoding(new Coding("http://hl7.org/fhir/restful-security-service", "SMART-on-FHIR", null));
		// cc.setText("OAuth2 using SMART-on-FHIR profile (see http://docs.smarthealthit.org)");

		Extension oauthExtension = new Extension();

		oauthExtension.setUrl("http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris");
		List<Extension> extensions = new ArrayList<>();
		if (StringUtils.trimToNull(this.tokenEndpoint) != null) {
			extensions.add(new Extension("token", new UriType(this.tokenEndpoint)));
		}

		if (StringUtils.trimToNull(this.authorizationEndpoint) != null) {
			extensions.add(new Extension("authorize", new UriType(this.authorizationEndpoint)));
		}

		if (StringUtils.trimToNull(this.managementEndpoint) != null) {
			extensions.add(new Extension("manage", new UriType(this.managementEndpoint)));
		}

		if (StringUtils.trimToNull(this.introspectionEndpoint) != null) {
			extensions.add(new Extension("introspect", new UriType(this.introspectionEndpoint)));
		}

		if (StringUtils.trimToNull(this.revocationEndpoint) != null) {
			extensions.add(new Extension("revoke", new UriType(this.revocationEndpoint)));
		}

		oauthExtension.setExtension(extensions);
		securityComponent.addExtension(oauthExtension);

		return securityComponent;
	}
}

